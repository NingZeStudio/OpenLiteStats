-- OpenLiteStats — 极简站点访问统计（OpenResty Lua）
-- 记录通过 WAF 的正常请求：请求 / 流量 / 独立 IP（位图近似）/ 按小时趋势；
-- 热门端点、来源（Referer host）、User-Agent、最近请求基于环形缓冲在展示时聚合。
-- 状态保存在 lua_shared_dict，定时快照到挂载目录实现持久化（重启恢复），
-- 目录不可写时自动退化为纯内存模式。文档见 OpenLiteStats/README.md。

local _M = { _VERSION = "1.0.0" }

local cjson = require "cjson.safe"

-- ───────────────────────── 配置 ─────────────────────────
local CONFIG = {
    -- shared dict 名称，须与 nginx.conf 中 lua_shared_dict 一致
    dict_name = "openlitestats",
    -- 统计页 URI（HTML 前缀 / JSON 前缀）；这两个前缀与 /security 不计入统计
    view_prefix = "/stats",
    data_prefix = "/stats/data",
    exclude_prefixes = { "/security", "/stats" },
    -- 快照持久化目录（容器内）；不可写时退化为纯内存模式
    data_dir = "/data/openlitestats",
    snapshot_interval = 60,
    -- 最近请求环形缓冲（热门端点 / 来源 / UA / 最近列表的聚合数据源）
    ring_capacity = 1000,
    -- 统计页展示的 Top 数与最近请求数
    top_n = 8,
    recent_n = 20,
    -- 独立 IP 位图位数（65536 位 = 8KB，线性计数修正碰撞）
    bm_bits = 65536,
    -- 单字段（URI / UA）最大长度；Referer 只保留 host
    log_field_max = 120,
    referer_field_max = 80,
    -- 小时趋势展示数（键 TTL 48h 自动回收）
    hours = 24,
}
_M.CONFIG = CONFIG

local BM_BYTES = CONFIG.bm_bits / 8
local POW = { 1, 2, 4, 8, 16, 32, 64, 128 }

-- ───────────────────────── 工具 ─────────────────────────
local function dict()
    return ngx.shared[CONFIG.dict_name]
end

-- IP 脱敏：IPv4 保留前两段，IPv6 保留前三组（与 OpenLiteWaf 统计页约定一致）
local function mask_ip(ip)
    if not ip or ip == "" then return "-" end
    if ip:find(":", 1, true) then
        local left, right = ip:match("^(.-)::(.*)$")
        local top = {}
        if left then
            for g in left:gmatch("[0-9a-fA-F]+") do
                top[#top + 1] = g
                if #top == 3 then break end
            end
            if #top < 3 then
                local right_groups = {}
                for g in right:gmatch("[0-9a-fA-F]+") do
                    right_groups[#right_groups + 1] = g
                end
                local zeros = 8 - #top - #right_groups
                while #top < 3 and zeros > 0 do
                    top[#top + 1] = "0"
                    zeros = zeros - 1
                end
                local r_idx = 1
                while #top < 3 and r_idx <= #right_groups do
                    top[#top + 1] = right_groups[r_idx]
                    r_idx = r_idx + 1
                end
            end
        else
            for g in ip:gmatch("[0-9a-fA-F]+") do
                top[#top + 1] = g
                if #top == 3 then break end
            end
        end
        while #top < 3 do
            top[#top + 1] = "0"
        end
        return table.concat(top, ":") .. "::*"
    end
    local a, b = ip:match("^(%d+%.%d+)%.%d+%.%d+$")
    if a then return a .. ".*.*" end
    return "*"
end

-- Referer 只保留 host（query 可能含 token 等敏感参数，且剥离 Basic Auth 凭据）
local function referer_host(ref)
    if not ref or ref == "" then return "-" end
    local host = ref:gsub("^%w+://", "")
    host = host:gsub("^//", "")
    host = host:match("^([^/]*)")
    host = host:gsub("^[^@]+@", "")
    if host == "" then return "-" end
    return host:sub(1, CONFIG.referer_field_max)
end

-- 位图位操作（纯算术实现，不依赖 bit 库）
local function bm_has(byte, i)
    return byte % (POW[i + 1] * 2) >= POW[i + 1]
end

local function linear_count(bm)
    if not bm then return 0 end
    local zeros = 0
    for i = 1, #bm do
        local b = bm:byte(i)
        for j = 0, 7 do
            if b % (POW[j + 1] * 2) < POW[j + 1] then zeros = zeros + 1 end
        end
    end
    -- 线性计数：n = -N·ln(z/N)；位图耗尽时退化为置位数不可知，按 N 计
    if zeros == 0 then return CONFIG.bm_bits end
    return math.floor(-CONFIG.bm_bits * math.log(zeros / CONFIG.bm_bits) + 0.5)
end

local function starts_with(s, prefix)
    return s ~= nil and s:sub(1, #prefix) == prefix
end

local function excluded(uri)
    for _, p in ipairs(CONFIG.exclude_prefixes) do
        if starts_with(uri, p) then return true end
    end
    return false
end

-- ───────────────────────── 记录 ─────────────────────────
-- 跨日滚动：清空今日计数与位图（键无 TTL，靠此处主动重置）
local function roll_date(d)
    local today = ngx.today()
    if d:get("cur_date") ~= today then
        d:set("cur_date", today)
        d:delete("t:req")
        d:delete("t:bytes")
        d:delete("u:bm")
    end
    return today
end

local function bump_hour(d)
    local h = math.floor(ngx.time() / 3600)
    local key = "h:" .. h
    if (d:incr(key, 1, 0) or 0) == 1 then
        d:expire(key, CONFIG.hours * 2 * 3600)
    end
end

local function bump_bitmap(d, ip)
    local bm = d:get("u:bm")
    if not bm then
        bm = ("\0"):rep(BM_BYTES)
        d:set("u:bm", bm)
    end
    local idx = ngx.crc32_short(ip or "") % CONFIG.bm_bits
    local byte_i = math.floor(idx / 8) + 1
    local bit_i = idx % 8
    local b = bm:byte(byte_i)
    if not bm_has(b, bit_i) then
        local nb = b + POW[bit_i + 1]
        d:set("u:bm", bm:sub(1, byte_i - 1) .. string.char(nb) .. bm:sub(byte_i + 1))
    end
end

-- access 阶段记录（仅统计通过 WAF 的请求；排除统计页自身）
function _M.record()
    local d = dict()
    if not d then return end
    local uri = ngx.var.uri or "/"
    if excluded(uri) then return end

    roll_date(d)
    local bytes = tonumber(ngx.var.bytes_sent) or 0

    d:incr("a:req", 1, 0)
    d:incr("a:bytes", bytes, 0)
    d:incr("t:req", 1, 0)
    d:incr("t:bytes", bytes, 0)
    bump_hour(d)
    bump_bitmap(d, ngx.var.remote_addr)

    -- 环形缓冲：最新覆盖最旧（展示时聚合 Top 与最近列表）
    local seq = (d:incr("seq", 1, 0) or 0)
    local entry = {
        t = ngx.time(),
        m = ngx.var.request_method or "-",
        u = uri:sub(1, CONFIG.log_field_max),
        b = bytes,
        r = referer_host(ngx.var.http_referer),
        a = (ngx.var.http_user_agent or "-"):sub(1, CONFIG.log_field_max),
        ip = mask_ip(ngx.var.remote_addr),
    }
    local ok, json = pcall(cjson.encode, entry)
    if ok and json then
        d:set("ring:" .. (seq - 1) % CONFIG.ring_capacity, json)
    end
end

-- ───────────────────── 展示时聚合 ─────────────────────
-- 从环形缓冲读取最近 count 条（新在前）
local function recent_entries(d, count)
    local seq = d:get("seq") or 0
    local total = math.min(seq, CONFIG.ring_capacity)
    local out = {}
    for i = 0, math.min(total, count) - 1 do
        local raw = d:get("ring:" .. (seq - i - 1) % CONFIG.ring_capacity)
        if raw then
            local ok, e = pcall(cjson.decode, raw)
            if ok and type(e) == "table" then out[#out + 1] = e end
        end
    end
    return out
end

-- 按字段聚合 Top（基于最近 ring_capacity 条，展示口径见 README）
local function top_from_entries(entries, field, limit)
    local counts, keys = {}, {}
    for _, e in ipairs(entries) do
        local k = e[field]
        if k and k ~= "-" then
            if counts[k] == nil then
                counts[k] = 0
                keys[#keys + 1] = k
            end
            counts[k] = counts[k] + 1
        end
    end
    table.sort(keys, function(x, y) return counts[x] > counts[y] end)
    local out = {}
    for i = 1, math.min(limit or CONFIG.top_n, #keys) do
        out[#out + 1] = { k = keys[i], n = counts[keys[i]] }
    end
    return out
end

-- 最近 24 个小时桶（旧→新）
local function hour_trend(d)
    local cur = math.floor(ngx.time() / 3600)
    local out = {}
    for i = CONFIG.hours - 1, 0, -1 do
        local h = cur - i
        out[#out + 1] = { t = h * 3600, n = d:get("h:" .. h) or 0 }
    end
    return out
end

local function build_view(d)
    local entries = recent_entries(d, CONFIG.ring_capacity)
    local saved_at = d:get("snap_at")
    return {
        name = "OpenLiteStats",
        version = _M._VERSION,
        date = d:get("cur_date") or ngx.today(),
        today = {
            req = d:get("t:req") or 0,
            bytes = d:get("t:bytes") or 0,
            unique_ips = linear_count(d:get("u:bm")),
        },
        alltime = {
            req = d:get("a:req") or 0,
            bytes = d:get("a:bytes") or 0,
        },
        hours = hour_trend(d),
        tops = {
            endpoints = top_from_entries(entries, "u"),
            referers = top_from_entries(entries, "r"),
            agents = top_from_entries(entries, "a"),
        },
        recent = recent_entries(d, CONFIG.recent_n),
        ring_seq = d:get("seq") or 0,
        ring_capacity = CONFIG.ring_capacity,
        snapshot_age = saved_at and (ngx.time() - saved_at) or nil,
    }
end

-- ───────────────────── 快照持久化 ─────────────────────
-- 每 snapshot_interval 秒由 worker 0 写快照（tmp + rename 原子替换），
-- init_by_lua 阶段恢复。快照失败（目录不可写等）只影响持久化，不影响统计。
local function snapshot_path()
    return CONFIG.data_dir .. "/snapshot.json"
end

-- 恢复（init_by_lua，master 阶段执行，无 worker 竞态；幂等）
function _M.init()
    local d = dict()
    if not d then return end
    local f = io.open(snapshot_path(), "rb")
    if not f then return end  -- 无快照 / 目录不可写：纯内存模式
    local raw = f:read("*a")
    f:close()
    local ok, snap = pcall(cjson.decode, raw)
    if not ok or type(snap) ~= "table" then return end

    d:set("a:req", snap.a_req or 0)
    d:set("a:bytes", snap.a_bytes or 0)
    if snap.date then d:set("cur_date", snap.date) end
    if snap.t_req then d:set("t:req", snap.t_req) end
    if snap.t_bytes then d:set("t:bytes", snap.t_bytes) end
    if snap.seq then d:set("seq", snap.seq) end
    if snap.bm and snap.bm ~= "" then
        local ok64, bm = pcall(ngx.decode_base64, snap.bm)
        if ok64 and bm and #bm == BM_BYTES then d:set("u:bm", bm) end
    end
    for _, e in ipairs(snap.ring or {}) do
        d:set("ring:" .. e.i, e.s)
    end
    for _, e in ipairs(snap.hours or {}) do
        local key = "h:" .. e.h
        d:set(key, e.n)
        d:expire(key, CONFIG.hours * 2 * 3600)
    end
    if snap.saved_at then d:set("snap_at", snap.saved_at) end
end

-- 写快照（worker 0 定时调用；_save 后缀供测试直接触发）
function _M._save(d)
    local seq = d:get("seq") or 0
    local total = math.min(seq, CONFIG.ring_capacity)
    local ring = {}
    for i = 0, total - 1 do
        local slot = (seq - i - 1) % CONFIG.ring_capacity
        local raw = d:get("ring:" .. slot)
        if raw then ring[#ring + 1] = { i = slot, s = raw } end
    end
    local hours = {}
    local cur = math.floor(ngx.time() / 3600)
    for i = 0, CONFIG.hours * 2 - 1 do
        local h = cur - i
        local n = d:get("h:" .. h)
        if n and n > 0 then hours[#hours + 1] = { h = h, n = n } end
    end
    local snap = {
        version = _M._VERSION,
        saved_at = ngx.time(),
        date = d:get("cur_date"),
        a_req = d:get("a:req") or 0,
        a_bytes = d:get("a:bytes") or 0,
        t_req = d:get("t:req") or 0,
        t_bytes = d:get("t:bytes") or 0,
        seq = seq,
        bm = ngx.encode_base64(d:get("u:bm") or ""),
        ring = ring,
        hours = hours,
    }
    local ok, json = pcall(cjson.encode, snap)
    if not ok or not json then return false end
    local tmp = snapshot_path() .. ".tmp"
    local f = io.open(tmp, "wb")
    if not f then return false end
    f:write(json)
    f:close()
    local renamed = os.rename(tmp, snapshot_path())
    if renamed then d:set("snap_at", ngx.time()) end
    return renamed
end

-- init_worker_by_lua：仅 worker 0 启动定时快照
function _M.timer()
    if ngx.worker.id() ~= 0 then return end
    ngx.timer.every(CONFIG.snapshot_interval, function(premature)
        if premature then return end
        local d = dict()
        if d then pcall(_M._save, d) end
    end)
end





-- ───────────────────── 公开统计页 ─────────────────────
local VIEW_HTML = [==[<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenLiteStats 访问统计</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"PingFang SC",sans-serif;max-width:860px;margin:2.25rem auto 3rem;padding:0 1.25rem;color:#23272e;background:#f5f6f8;-webkit-font-smoothing:antialiased}
h1{font-size:1.3rem;font-weight:700;margin:0 0 1.4rem;letter-spacing:.01em}
.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:.8rem}
.card{background:#fff;border:1px solid #e6e8eb;border-radius:10px;padding:.9rem 1.05rem .85rem;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card span{display:block;font-size:.72rem;color:#8a919c;letter-spacing:.02em}
.card b{display:block;margin-top:.35rem;font-size:1.45rem;font-weight:650;font-variant-numeric:tabular-nums;letter-spacing:-.01em;color:#23272e}
h2{display:flex;align-items:center;gap:.7rem;font-size:.8rem;font-weight:600;color:#66707c;margin:2.1rem 0 .75rem;letter-spacing:.04em}
h2::after{content:"";flex:1;height:1px;background:#e6e8eb}
h2 small{font-weight:400;font-size:.72rem;color:#98a1ab;letter-spacing:0}
.panel{background:#fff;border:1px solid #e6e8eb;border-radius:10px;padding:1.05rem 1.1rem;box-shadow:0 1px 2px rgba(16,24,40,.04)}
#trend rect{transition:opacity .15s}
#trend rect:hover{opacity:1}
.barrow{display:flex;align-items:center;gap:.8rem;margin:.55rem 0;font-size:.78rem}
.barrow .lbl{flex-shrink:0;color:#3f4750;word-break:break-all;max-width:14em}
.barrow .track{flex:1;height:8px;background:#f0f2f4;border-radius:999px;overflow:hidden}
.bar{display:block;height:100%;background:#d64545;border-radius:999px;min-width:2px}
.barrow .num{min-width:3.5em;text-align:right;font-variant-numeric:tabular-nums;color:#23272e;flex-shrink:0}
.tablewrap{background:#fff;border:1px solid #e6e8eb;border-radius:10px;box-shadow:0 1px 2px rgba(16,24,40,.04);overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:720px}
th,td{padding:.5rem .8rem;text-align:left;border-bottom:1px solid #f1f3f5;font-size:.78rem;white-space:nowrap;vertical-align:top}
th{color:#8a919c;font-weight:600;font-size:.72rem;background:#fafbfc;letter-spacing:.03em}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#fafbfc}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;color:#66707c}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #e6e8eb;color:#98a1ab;font-size:.73rem;line-height:1.7}
.noscript{color:#b42318;font-size:.85rem}
.empty{color:#a3aab3;font-size:.82rem;padding:1.2rem 0;text-align:center}
@media (max-width:520px){body{margin-top:1.25rem;padding:0 .9rem}h1{font-size:1.1rem}.card b{font-size:1.25rem}th,td{padding:.45rem .6rem}}
@media (min-width:640px){.cards{grid-template-columns:repeat(3,1fr)}}
</style>
</head>
<body>
<header><h1>OpenLiteStats 访问统计</h1></header>

<div class="cards">
  <div class="card"><span>今日请求</span><b id="st-treq">–</b></div>
  <div class="card"><span>今日流量</span><b id="st-tbytes">–</b></div>
  <div class="card"><span>独立 IP（近似）</span><b id="st-uip">–</b></div>
  <div class="card"><span>累计请求</span><b id="st-areq">–</b></div>
  <div class="card"><span>累计流量</span><b id="st-abytes">–</b></div>
  <div class="card"><span>今日速率（次/分钟）</span><b id="st-rate">–</b></div>
</div>

<h2>最近 24 小时请求趋势</h2>
<div class="panel" id="trend"><div class="empty">加载中…</div></div>

<h2>热门端点 <small>最近 1000 条请求</small></h2>
<div class="panel" id="endpoints"><div class="empty">加载中…</div></div>

<h2>来源 Top <small>Referer host · 最近 1000 条</small></h2>
<div class="panel" id="referers"><div class="empty">加载中…</div></div>

<h2>User-Agent Top <small>最近 1000 条</small></h2>
<div class="panel" id="agents"><div class="empty">加载中…</div></div>

<h2>最近请求 <small>最新 20 条 · IP 已脱敏</small></h2>
<div class="tablewrap">
<table>
<thead><tr><th>时间</th><th>方法</th><th>端点</th><th>流量</th><th>来源 IP</th><th>来源页</th><th>User-Agent</th></tr></thead>
<tbody id="rows"></tbody>
</table>
</div>

<footer id="foot">OpenLiteStats</footer>

<noscript><p class="noscript">此页面需要启用 JavaScript 才能展示统计数据。</p></noscript>

<script>
function asArr(x){
  if(Array.isArray(x))return x;
  if(x&&typeof x==="object"){var a=[];for(var k in x)a.push(x[k]);return a;}
  return [];
}
function el(id){return document.getElementById(id);}
function fmtT(ts){var d=new Date(ts*1000),p=function(n){return(n<10?"0":"")+n};return p(d.getHours())+":"+p(d.getMinutes());}
function fmtBytes(n){
  if(n>=1073741824)return (n/1073741824).toFixed(2)+" GB";
  if(n>=1048576)return (n/1048576).toFixed(1)+" MB";
  if(n>=1024)return (n/1024).toFixed(1)+" KB";
  return n+" B";
}
function clearBox(id){var b=el(id);b.textContent="";return b;}
function drawBars(box,items,max){ // DOM 渲染：lbl 可能含用户可控内容，禁止 innerHTML 拼接
  for(var i=0;i<items.length;i++){
    var row=document.createElement("div");row.className="barrow";
    var lbl=document.createElement("span");lbl.className="lbl";lbl.textContent=items[i].k;
    var track=document.createElement("span");track.className="track";
    var bar=document.createElement("span");bar.className="bar";bar.style.width=Math.round(items[i].n/max*100)+"%";
    var num=document.createElement("span");num.className="num";num.textContent=items[i].n;
    track.appendChild(bar);row.appendChild(lbl);row.appendChild(track);row.appendChild(num);box.appendChild(row);
  }
}
function drawTops(id,list){
  list=asArr(list);var box=clearBox(id);
  if(list.length===0){box.innerHTML='<div class="empty">暂无数据</div>';return;}
  var max=1;for(var i=0;i<list.length;i++){if(list[i].n>max)max=list[i].n;}
  drawBars(box,list,max);
}
function drawTrend(rows){
  rows=asArr(rows);var box=el("trend");
  if(rows.length===0){box.innerHTML='<div class="empty">暂无数据</div>';return;}
  var W=640,H=170,P=16,max=1;
  for(var i=0;i<rows.length;i++){if(rows[i].n>max)max=rows[i].n;}
  var bw=(W-P*2)/rows.length;
  var base=H-24,top=16;
  var s='<svg viewBox="0 0 '+W+" "+H+'" width="100%" height="170" role="img" aria-label="请求趋势图">';
  for(var g=1;g<=3;g++){
    var gy=base-(base-top)*g/4;
    s+='<line x1="'+P+'" y1="'+gy.toFixed(1)+'" x2="'+(W-P)+'" y2="'+gy.toFixed(1)+'" stroke="#f0f2f4"/>';
  }
  s+='<line x1="'+P+'" y1="'+base+'" x2="'+(W-P)+'" y2="'+base+'" stroke="#e6e8eb"/>';
  for(var j=0;j<rows.length;j++){
    var h=Math.round(rows[j].n/max*(base-top));
    if(rows[j].n>0){
      s+='<rect x="'+(P+j*bw).toFixed(1)+'" y="'+(base-h)+'" width="'+Math.max(bw-2,2).toFixed(1)+'" height="'+h+'" rx="2" fill="#d64545" opacity="0.85">'
        +'<title>'+rows[j].n+' 次 / '+fmtT(rows[j].t)+'</title></rect>';
    }
  }
  s+='<text x="'+P+'" y="'+(H-6)+'" font-size="10" fill="#98a1ab">'+fmtT(rows[0].t)+'</text>';
  s+='<text x="'+(W-P)+'" y="'+(H-6)+'" font-size="10" fill="#98a1ab" text-anchor="end">'+fmtT(rows[rows.length-1].t)+'</text>';
  s+='<text x="'+P+'" y="10" font-size="10" fill="#98a1ab">峰值 '+max+' 次/小时</text>';
  s+='</svg>';
  box.innerHTML=s;
}
function fetchData(){
  fetch("REPLACE_VIEW_DATA_URI").then(function(r){return r.json();}).then(function(j){
    el("st-treq").textContent=j.today.req;
    el("st-tbytes").textContent=fmtBytes(j.today.bytes||0);
    el("st-uip").textContent=j.today.unique_ips;
    el("st-areq").textContent=j.alltime.req;
    el("st-abytes").textContent=fmtBytes(j.alltime.bytes||0);
    el("st-rate").textContent=(j.today.req/1440).toFixed(1);
    el("foot").textContent="OpenLiteStats v"+j.version+" · 统计日期 "+j.date;
    drawTrend(j.hours);
    drawTops("endpoints",j.tops.endpoints);
    drawTops("referers",j.tops.referers);
    drawTops("agents",j.tops.agents);
    var rows=asArr(j.recent),tb=clearBox("rows");
    if(rows.length===0){
      var tr=document.createElement("tr"),td=document.createElement("td");
      td.colSpan=7;td.className="empty";td.textContent="暂无请求记录";tr.appendChild(td);tb.appendChild(tr);
    }else{
      for(var i=0;i<rows.length;i++){
        var e=rows[i],tr=document.createElement("tr");
        var td1=document.createElement("td");td1.className="num";td1.textContent=fmtT(e.t);
        var td2=document.createElement("td");td2.textContent=e.m;
        var td3=document.createElement("td");td3.textContent=e.u;
        var td4=document.createElement("td");td4.className="num";td4.textContent=fmtBytes(e.b||0);
        var td5=document.createElement("td");td5.style.fontFamily="ui-monospace,Menlo,monospace";td5.textContent=e.ip;
        var td6=document.createElement("td");td6.textContent=e.r;
        var td7=document.createElement("td");td7.textContent=e.a;
        tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);tr.appendChild(td4);
        tr.appendChild(td5);tr.appendChild(td6);tr.appendChild(td7);
        tb.appendChild(tr);
      }
    }
  }).catch(function(){});
}
fetchData();
setInterval(fetchData,30000);
</script>
</body>
</html>
]==]

function _M.view()
    local d = dict()
    local uri = ngx.var.uri or CONFIG.view_prefix

    -- JSON 输出：/stats/data
    if uri == CONFIG.data_prefix then
        ngx.header.content_type = "application/json; charset=utf-8"
        ngx.header["Cache-Control"] = "no-store"
        ngx.say(cjson.encode(build_view(d)) or "{}")
        return
    end

    -- HTML 输出：/stats（数据 URI 经占位符注入，避免硬编码前缀）；
    -- gsub 有两个返回值，括号确保只传替换后的字符串（否则替换次数会被拼进页面）
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say((VIEW_HTML:gsub("REPLACE_VIEW_DATA_URI", CONFIG.data_prefix)))
end

_M._mask_ip = mask_ip
_M._referer_host = referer_host

return _M
