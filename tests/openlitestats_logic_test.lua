-- OpenLiteStats 逻辑回归测试（Lua 5.1，stub ngx 运行真实模块代码）
-- 用法：lua5.1 OpenLiteStats/tests/openlitestats_logic_test.lua
-- 覆盖：记录与计数、排除前缀、独立 IP 位图、IP/Referer 脱敏、跨日滚动、
-- 小时趋势、快照持久化往返、统计页 JSON/HTML、log 阶段拦截门控。

local fail = 0
local function ok(cond, name)
    if cond then
        print("PASS  " .. name)
    else
        fail = fail + 1
        print("FAIL  " .. name)
    end
end

local BASE = debug.getinfo(1, "S").source:gsub("^@", ""):gsub("[^/]+$", "") .. ".."
local MOD_PATH = BASE .. "/lua/openlitestats.lua"
local LOG_PATH = BASE .. "/lua/log.lua"
package.path = BASE .. "/lua/?.lua;" .. package.path

local NOW = 1788300000.0
local TODAY = "2026-09-01"
local TIMER_CB = nil

-- ── 共享 dict mock（支持 TTL 惰性过期）──
local function newdict()
    local d = { store = {} }
    function d:_live(k)
        local e = self.store[k]
        if e and e.exp and NOW >= e.exp then
            self.store[k] = nil
            return nil
        end
        return e
    end
    function d:get(k)
        local e = self:_live(k)
        return e and e.v or nil
    end
    function d:set(k, v, ex)
        self.store[k] = { v = v, exp = ex and (NOW + ex) or nil }
        return true
    end
    function d:incr(k, delta, init)
        local e = self:_live(k)
        if not e then
            e = { v = init or 0, exp = nil }
            self.store[k] = e
        end
        e.v = e.v + delta
        return e.v
    end
    function d:expire(k, t)
        local e = self:_live(k)
        if e then
            e.exp = NOW + t
            return true
        end
        return false
    end
    function d:delete(k) self.store[k] = nil return true end
    function d:add(k, v, ex)
        if self:_live(k) then return false end
        self.store[k] = { v = v, exp = ex and (NOW + ex) or nil }
        return true
    end
    return d
end

-- ── JSON 完整编解码 stub（快照含嵌套表/数组）──
local function json_enc(v)
    local t = type(v)
    if v == nil then return "null" end
    if t == "boolean" then return tostring(v) end
    if t == "number" then
        if v == math.floor(v) and math.abs(v) < 2 ^ 53 then
            return string.format("%d", v)
        end
        return tostring(v)
    end
    if t == "string" then
        return '"' .. v:gsub('[%c"\\]', function(c)
            if c == '"' then return '\\"' end
            if c == "\\" then return "\\\\" end
            if c == "\n" then return "\\n" end
            if c == "\r" then return "\\r" end
            if c == "\t" then return "\\t" end
            return string.format("\\u%04x", c:byte())
        end) .. '"'
    end
    if t == "table" then
        if #v > 0 then
            local parts = {}
            for i = 1, #v do parts[i] = json_enc(v[i]) end
            return "[" .. table.concat(parts, ",") .. "]"
        end
        local parts = {}
        for k, val in pairs(v) do
            parts[#parts + 1] = json_enc(tostring(k)) .. ":" .. json_enc(val)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
    error("cannot encode " .. t)
end

local function json_dec(s, i)
    i = i or 1
    local c = s:sub(i, i)
    while c == " " or c == "," or c == ":" or c == "\n" or c == "\r" or c == "\t" do
        i = i + 1
        c = s:sub(i, i)
    end
    if c == "{" then
        local obj = {}
        i = i + 1
        while true do
            c = s:sub(i, i)
            if c == "}" then return obj, i + 1 end
            local k
            k, i = json_dec(s, i)
            local v
            v, i = json_dec(s, i)
            obj[k] = v
        end
    elseif c == "[" then
        local arr = {}
        i = i + 1
        while true do
            c = s:sub(i, i)
            if c == "]" then return arr, i + 1 end
            local v
            v, i = json_dec(s, i)
            arr[#arr + 1] = v
        end
    elseif c == '"' then
        local out = {}
        i = i + 1
        while true do
            local ch = s:sub(i, i)
            if ch == "\\" then
                local n = s:sub(i + 1, i + 1)
                if n == "n" then out[#out + 1] = "\n"
                elseif n == "r" then out[#out + 1] = "\r"
                elseif n == "t" then out[#out + 1] = "\t"
                elseif n == "u" then
                    out[#out + 1] = string.char(tonumber(s:sub(i + 2, i + 5), 16) or 63)
                    i = i + 4
                else out[#out + 1] = n end
                i = i + 2
            elseif ch == '"' then
                return table.concat(out), i + 1
            else
                out[#out + 1] = ch
                i = i + 1
            end
        end
    else
        local num = s:match("^%-?%d+%.?%d*[eE]?[-+]?%d*", i)
        if num then return tonumber(num), i + #num end
        if s:sub(i, i + 3) == "true" then return true, i + 4 end
        if s:sub(i, i + 4) == "false" then return false, i + 5 end
        if s:sub(i, i + 3) == "null" then return nil, i + 4 end
        error("bad json at " .. i)
    end
end

local B64A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function b64e(data)
    return ((data:gsub('.', function(x)
        local r, b = '', x:byte()
        for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if #x < 6 then return '' end
        local c = tonumber(x, 2) + 1
        return B64A:sub(c, c)
    end) .. ({ '', '==', '=' })[#data % 4 + 1])
end
local function b64d(data)
    data = string.gsub(data, '[^' .. B64A .. '=]', '')
    return (data:gsub('.', function(x)
        if x == '=' then return '' end
        local r, f = '', (B64A:find(x) - 1)
        for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if #x ~= 8 then return '' end
        return string.char(tonumber(x, 2))
    end))
end

local SAID = nil
ngx = {
    now = function() return NOW end,
    time = function() return math.floor(NOW) end,
    today = function() return TODAY end,
    crc32_short = function(s)
        local h = 5381
        for i = 1, #s do h = (h * 33 + s:byte(i)) % 4294967296 end
        return h
    end,
    encode_base64 = b64e,
    decode_base64 = b64d,
    worker = { id = function() return 0 end },
    timer = { every = function(_, cb) TIMER_CB = cb return true end },
    shared = { openlitestats = newdict() },
    var = {},
    ctx = {},
    header = {},
    say = function(...) SAID = table.concat({ ... }) end,
}

package.loaded["cjson.safe"] = {
    encode = json_enc,
    decode = function(s)
        local ok, v, i = pcall(json_dec, s)
        if ok and v ~= nil then return v end
        return nil
    end,
}

local mod = dofile(MOD_PATH)

local function request(opts)
    ngx.var.uri = opts.uri or "/"
    ngx.var.remote_addr = opts.ip or "1.2.3.4"
    ngx.var.bytes_sent = opts.bytes
    ngx.var.http_referer = opts.ref
    ngx.var.http_user_agent = opts.ua
    ngx.var.request_method = opts.method or "GET"
    ngx.ctx = {}
    mod.record()
    return ngx.shared.openlitestats
end

local function fresh()
    ngx.shared.openlitestats = newdict()
    ngx.ctx = {}
    return dofile(MOD_PATH)
end

local function stats_json(uri)
    ngx.var.uri = uri
    ngx.var.request_uri = uri
    SAID = nil
    pcall(function() mod.view() end)
    return SAID
end

-- T1 记录与计数
local d = request({ uri = "/v1/log", bytes = 1234 })
ok(d:get("a:req") == 1 and d:get("t:req") == 1, "请求计数写入")
ok(d:get("a:bytes") == 1234 and d:get("t:bytes") == 1234, "流量计数写入")

-- T2 排除前缀：统计页自身与 WAF 页不计入
request({ uri = "/stats" })
request({ uri = "/stats/data" })
request({ uri = "/security" })
ok(d:get("a:req") == 1, "排除前缀不计数")

-- T3 独立 IP 位图（此前的默认 IP 1.2.3.4 已占一位，共 3 个独立 IP）
request({ uri = "/a", ip = "5.6.7.8" })
request({ uri = "/a", ip = "5.6.7.8" })
request({ uri = "/a", ip = "9.9.9.9" })
local js = stats_json("/stats/data")
ok(js and js:find('"unique_ips":3', 1, true) ~= nil, "独立 IP 去重（位图线性计数）")

-- T4 脱敏：IP 与 Referer host
request({
    uri = "/x", ip = "192.168.55.77",
    ref = "https://example.com/page?token=secret",
    ua = "TestBot/1.0",
})
js = stats_json("/stats/data")
ok(js and js:find("192.168.*.*", 1, true) ~= nil
    and js:find("192.168.55.77", 1, true) == nil, "日志 IP 已脱敏")
ok(js and js:find("example.com", 1, true) ~= nil
    and js:find("token=secret", 1, true) == nil, "Referer 仅保留 host")

-- T5 跨日滚动：今日清零、累计保留、位图重置
TODAY = "2026-09-02"
request({ uri = "/y", ip = "5.6.7.8", bytes = 10 })
js = stats_json("/stats/data")
ok(js and js:find('"req":1', 1, true) ~= nil, "跨日后今日计数重置")
ok(js and js:find('"unique_ips":1', 1, true) ~= nil, "跨日后独立 IP 重置")
local view = package.loaded["cjson.safe"].decode(js)
ok(view and view.alltime.req == 6, "跨日后累计请求保留")

-- T6 小时趋势（此前的请求全部落在同一小时桶，共 6 次）
local hour_key = "h:" .. math.floor(NOW / 3600)
ok(ngx.shared.openlitestats:get(hour_key) == 6, "小时桶计数写入")

-- T7 快照持久化往返
do
    local dir = "/data/data/com.termux/files/usr/tmp/olstats-snaptest"
    os.execute("mkdir -p " .. dir)
    os.remove(dir .. "/snapshot.json")
    mod.CONFIG.data_dir = dir
    ok(mod._save(ngx.shared.openlitestats) == true, "快照写入成功")
    -- 新 dict + 新模块：模拟重启后的 init 恢复
    ngx.shared.openlitestats = newdict()
    local mod2 = dofile(MOD_PATH)
    mod2.CONFIG.data_dir = dir
    mod2.init()
    local d2 = ngx.shared.openlitestats
    ok(d2:get("a:req") == 6 and (d2:get("t:req") or 0) == 1, "计数恢复")
    ok((d2:get("seq") or 0) == 6, "环形缓冲序列恢复")
    ok(d2:get("ring:0") ~= nil or d2:get("ring:1") ~= nil, "环形缓冲内容恢复")
    ok(d2:get("u:bm") ~= nil and #d2:get("u:bm") == 8192, "独立 IP 位图恢复")
    js = stats_json("/stats/data")
    ok(js and js:find('"unique_ips":1', 1, true) ~= nil, "恢复后独立 IP 估算正确")
    os.remove(dir .. "/snapshot.json")
end

-- T8 Top 聚合排序
do
    fresh()
    for i = 1, 3 do request({ uri = "/hot", ip = "10.0.0." .. i }) end
    request({ uri = "/warm", ip = "10.0.0.9" })
    js = stats_json("/stats/data")
    ok(js and js:find('"k":"/hot"', 1, true) ~= nil
        and js:find('"n":3', 1, true) ~= nil, "热门端点聚合计数")
    ok(js and js:find('"k":"/hot"', 1, true) ~= nil
        and js:find('"k":"/warm"', 1, true) ~= nil, "Top 含全部端点")
end

-- T9 页面输出
js = stats_json("/stats")
ok(js and js:find("OpenLiteStats 访问统计", 1, true) ~= nil, "HTML 统计页输出")
ok(js and js:find("/stats/data", 1, true) ~= nil, "HTML 注入数据端点 URI")
ok(js and js:find("REPLACE_VIEW_DATA_URI", 1, true) == nil, "占位符已替换")
ok(js and js:match("</html>%s*$") ~= nil, "HTML 输出无多余尾巴（gsub 次数不外泄）")

-- T10 log.lua 门控：被 WAF 拦截的请求不记录
do
    fresh()
    ngx.var.uri = "/v1/log"
    ngx.var.remote_addr = "7.7.7.7"
    ngx.var.bytes_sent = "100"
    ngx.var.request_method = "GET"
    ngx.var.http_referer = nil
    ngx.var.http_user_agent = nil
    ngx.ctx = { olw_blocked = true }
    dofile(LOG_PATH)
    ok((ngx.shared.openlitestats:get("a:req") or 0) == 0, "被拦截请求不计入")
    ngx.ctx = {}
    dofile(LOG_PATH)
    ok((ngx.shared.openlitestats:get("a:req") or 0) == 1, "正常请求经 log.lua 计入")
end

print(fail == 0 and "全部通过" or (fail .. " 项失败"))
os.exit(fail == 0 and 0 or 1)
