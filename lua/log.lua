-- OpenLiteStats 记录入口：由 docker/nginx/default.conf 中的 log_by_lua_file 调用。
-- log 阶段执行（响应已发送，bytes_sent 可用）。只统计未被 OpenLiteWaf
-- 拦截的请求（deny 时 WAF 会设置 ngx.ctx.olw_blocked）。
if not ngx.ctx.olw_blocked then
    require("openlitestats").record()
end
