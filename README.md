# OpenLiteStats

运行在 nginx 容器内的极简站点访问统计（OpenResty Lua）。统计通过 OpenLiteWaf 的正常请求：请求量、流量、独立 IP（近似）、按小时趋势，以及基于最近请求聚合的热门端点、来源（Referer host）与 User-Agent。所有状态保存在 `lua_shared_dict`，定时快照到挂载目录实现持久化（重启自动恢复）。许可证：MIT。

代码结构：

```
OpenLiteStats/
├── lua/
│   ├── openlitestats.lua  # 核心模块：记录、聚合、快照持久化、统计页输出
│   ├── log.lua            # log_by_lua_file 入口（记录）
│   └── view.lua           # content_by_lua_file 入口（/stats 页面与 JSON）
└── tests/                 # 回归测试（stub ngx，lua5.1 运行）
```

## 统计口径

记录发生在 log 阶段（响应已发送，`bytes_sent` 可用）。以下请求不计入：

- 被 OpenLiteWaf 拦截的请求（WAF 在 deny 时设置 `ngx.ctx.olw_blocked`，拦截情况由 `/security` 页面统计）；
- `/security`、`/stats` 前缀（两套统计页自身，避免自引用污染热门端点）。

流量为出站字节数（`bytes_sent`），含应用响应与静态内容。独立 IP 用 64K 位图 + 线性计数估算（8KB 内存，约 0.4% 量级误差），按日重置；同一 IP 的 PV 只计一次。热门端点 / 来源 / UA 的 Top 基于最近 1000 条请求的环形缓冲在展示时聚合，不代表全量历史。

隐私约定：IP 一律脱敏（IPv4 保留前两段，IPv6 保留前三组），Referer 只保留 host（query 可能含 token 等敏感参数），URI 只取规范化路径（不含 query）。完整数据仅存于内存与服务器本地快照文件。

## 页面与接口

- `GET /stats`：HTML 统计页，内联 JS 每 30 秒轮询刷新，需要 JavaScript。
- `GET /stats/data`：JSON 汇总。`today`（`req` / `bytes` / `unique_ips`）、`alltime`（`req` / `bytes`）、`hours`（最近 24 个小时桶）、`tops`（`endpoints` / `referers` / `agents`，各 Top 8）、`recent`（最近 20 条请求，已脱敏）、`ring_seq` / `ring_capacity`、`snapshot_age`（距上次快照秒数）。

今日与累计的切分按服务器本地日期（`ngx.today()`）滚动：跨日时今日计数与独立 IP 位图重置，累计值保留。

## 持久化

worker 0 每 60 秒将内存状态（计数、位图、环形缓冲、小时桶）写为 `data/snapshot.json`（临时文件 + rename 原子替换），`init_by_lua` 阶段恢复。极端情况丢失最近 60 秒数据。`data/` 目录不可写时自动退化为纯内存模式，只影响持久化、不影响统计。

全部配置集中在 `lua/openlitestats.lua` 顶部的 `CONFIG`（dict 名称、前缀、排除列表、快照间隔、环形容量、Top 数、位图位数等）。

## 部署

与 OpenLiteWaf 同容器运行（复用其 nginx.conf 中的 package path 与 `lua_shared_dict openlitestats 32m`）：

```yaml
volumes:
  - ../OpenLiteStats/lua:/usr/local/openresty/nginx/lstats:ro
  - ../OpenLiteStats/data:/data/openlitestats        # 快照持久化目录
```

```nginx
log_by_lua_file /usr/local/openresty/nginx/lstats/log.lua;   # 与 access_by_lua_file 同级
location = /stats      { content_by_lua_file /usr/local/openresty/nginx/lstats/view.lua; }
location = /stats/data { content_by_lua_file /usr/local/openresty/nginx/lstats/view.lua; }
```

## 回归测试

```bash
luac5.1 -p OpenLiteStats/lua/*.lua
lua5.1 OpenLiteStats/tests/openlitestats_logic_test.lua
```

## 注意事项

- 统计页为公开端点，受 WAF CC 限流保护；如需限制访问，可在 nginx 层为 `/stats` 加 auth_basic 或 allow/deny。
- 多 worker 并发下 shared dict 的 incr 原子但位图置位存在极小概率竞态（读改写），对近似统计无实际影响。
- 若 nginx 前有 CDN，`remote_addr` 是节点 IP，独立 IP 与日志 IP 均不准确，需先配置 real_ip。
