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
- CORS 预检（`OPTIONS`）：应用层中间件直接短路应答、不进业务，计入会让浏览器流量的请求数结构性翻倍；
- `/security`、`/stats` 前缀（两套统计页自身，避免自引用污染热门端点）；
- `/v1/telemetry`、`/1/telemetry` 前缀（前端与启动器的性能/错误遥测上报）：机器流量而非访问行为，实际占比过半，且每个上报方都带独立 IP，会把「独立 IP 数」撑成「在线设备数」；
- `/v1/admin`、`/1/admin` 前缀（管理后台轮询，80 余个子路径），属运维流量，不该出现在站点访问榜单。

排除按路径段边界判定（`/v1/admin/logs` 排除，`/v1/administrator` 不排除），排除前缀列表里出现空串不会停掉全站统计（`starts_with` 显式拒绝空前缀）。`/securityXYZ`、`/statsXYZ` 这类相似路径自 v1.1.0 起计入统计——它们是本该 404 的真实请求，今日计数会因此有一个小台阶。

流量为出站字节数（`bytes_sent`），含应用响应与静态内容。独立 IP 用 64K 位图 + 线性计数估算（8KB 内存，约 0.4% 量级误差），按日重置；同一 IP 的 PV 只计一次。热门端点 / 来源 / UA 的 Top 基于最近 1000 条请求的环形缓冲在展示时聚合，不代表全量历史。

热门端点的聚合键做了路径模板化：`/v1/raw/{id}/main.log` 归并为 `/v1/raw/:id/main.log`、长十六进制的分析 cacheKey 归并为 `:hash`，否则每个日志实例各占一键、Top 8 全被 ID 变体占满。口径与后端 `TelemetryService::cleanEndpoint` 一致（ID = 1 位存储标识 + 6 位随机字符，且段内必须含数字，避免把 `preview`、`backups` 这类 7 位纯字母路由折叠掉）。归一只发生在聚合侧，`recent` 列表仍显示原始路径，便于按实例排查。

隐私约定：IP 一律脱敏（IPv4 保留前两段，IPv6 保留前三组），Referer 只保留 host（query 可能含 token 等敏感参数），URI 只取规范化路径（不含 query）。完整数据仅存于内存与服务器本地快照文件。

## 页面与接口

- `GET /stats`：HTML 统计页，内联 JS 每 30 秒轮询刷新，需要 JavaScript。
- `GET /stats/data`：JSON 汇总。`today`（`req` / `bytes` / `unique_ips`）、`alltime`（`req` / `bytes`）、`hours`（最近 24 个小时桶）、`tops`（`endpoints` / `referers` / `agents`，各 Top 8）、`recent`（最近 20 条请求，已脱敏）、`ring_seq` / `ring_capacity`、`snapshot_age`（距上次快照秒数）。

今日与累计的切分按服务器本地日期（`ngx.today()`）滚动：跨日时今日计数与独立 IP 位图重置，累计值保留。

## 持久化

worker 0 每 60 秒将内存状态（计数、位图、环形缓冲、小时桶）写为 `data/snapshot.json`（临时文件 + rename 原子替换），`init_by_lua` 阶段恢复。极端情况丢失最近 60 秒数据。`data/` 目录不可写时自动退化为纯内存模式，只影响持久化、不影响统计。

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `dict_name` | `openlitestats` | 须与 `lua_shared_dict` 名一致 |
| `view_prefix` / `data_prefix` | `/stats`、`/stats/data` | 统计页 URI |
| `exclude_prefixes` | `/security`、`/stats`、`/v1|/1/telemetry`、`/v1|/1/admin` | 不计入统计的前缀（按路径段边界） |
| `data_dir` / `snapshot_interval` | `/data/openlitestats` / 60 | 快照目录 / 写盘间隔 |
| `ring_capacity` | 1000 | 最近请求环形缓冲容量（Top 与 recent 的数据源） |
| `top_n` / `recent_n` | 8 / 20 | 页面展示的 Top 数与最近请求数 |
| `bm_bits` | 65536 | 独立 IP 位图位数 |
| `log_field_max` / `referer_field_max` | 120 / 80 | 单字段截断长度 |
| `hours` | 24 | 小时趋势展示数 |

OPTIONS 预检的排除写死在 `record()` 内（不是配置项）：它不是可调整的口径，而是"预检不是访问行为"的事实判断。

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
