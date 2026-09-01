-- OpenLiteStats 统计页入口：由 docker/nginx/default.conf 中的 content_by_lua_file 调用。
-- HTML：/stats　JSON：/stats/data
require("openlitestats").view()
