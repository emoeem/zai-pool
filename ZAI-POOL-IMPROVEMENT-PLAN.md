# zai-pool 改进计划（基于 2026-11-21 源码审查）

审查来源：GitHub main 分支静态审查（df2d7c8）。本文件记录每个问题的处置状态；
修复以 tests/ 回归 + CI 通过为进入下一阶段的门槛。

## Phase 6 模块化（2026-11-22 首次尝试：回滚，推迟）

- 尝试：AST 按顶层节点抽取 core 域（Account/Device/Pool/锁/桶/解析器/validate_security/UPSTREAMS）到 `zai_pool/core.py`
- 结果：三轮补残留名称（MAX_BODY_BYTES/UPSTREAMS/模块名冲突 conftest 已修）后仍有 15 failed/27 errors——单文件内隐式耦合比预估深
- 处置：**按 §6.2 纪律整体回滚**（行为零变化不可让步；观察期网关零影响），71 tests + 13 验收恢复绿
- 保留成果：`tests/conftest.py` 模块注册名改为 `zp_entry`（消除与未来 `zai_pool` 包的命名冲突，下次迁移的前置修复）
- 下次迁移前置条件：先把 zai-pool.py 内部按域加显式边界注释 + 为隐式共享名（MAX_BODY_BYTES/UPSTREAMS/BILLING_*）建立单一所有权，再机械搬运

## Phase 4：性能、连接与资源管理（2026-11-22）

| 计划项 | 处置 |
|---|---|
| 4.1 并发连接控制（max_connections/max_queued/max_sse_connections） | ✅ `BoundedServer`：活跃连接超限立即 503（不无限建线程）；SSE 独立配额占用/释放（跨 attempt 任何退出路径）；backlog 可配 |
| 4.2 SSE 增量解析器 | ✅ `SSEUsageParser`：事件缓冲→行解析→usage 提取，跨 chunk 拼接、单 chunk 多事件、坏行忽略；协议字节原样透传（解析只读不改） |
| 4.3 超时体系分离 | ✅ 非流式 `request_timeout` / 流式按块 `stream_idle_timeout`（read 抛 OSError 即终止）/ `connect_timeout`（TCP+TLS+代理握手），全部可配 |
| 4.4 请求限流 | ✅ 内存令牌桶：全局限流 + 设备级限流，超限标准 429（`rate_limited_local`），**与账号 429 状态机完全隔离**（测试断言零冷却）；无 Redis 强依赖 |
| 4.5 压力测试 | ✅ `tests/performance/bench.py`（json/sse/mixed，阶梯 1/10/25/50/100）：P50/P95/P99/RPS/错误率/槽位泄漏判定；CI 只跑轻量冒烟（`test_bench_smoke.py`），机器无关 |
| 基线数据（本机，mock 上游） | 100 并发 SSE：0 错误 0 槽位泄漏，RPS≈1311，P99=29ms；真实上游数字待填 key 后复测 |

## 第二阶段：生产环境验收与稳定性收口（2026-11-22）

| 项 | 处置 |
|---|---|
| zacc-web Origin 校验为子串判断（127.0.0.1.attacker.example 可绕过、缺失 Origin 放行） | ✅ urlsplit 精确比对 scheme+hostname+port，拒绝缺失/畸形/端口不符；Host 头同检（防 DNS rebinding） |
| 写操作无独立 CSRF Token | ✅ CSRF_TOKEN（启动随机，经 /api/list 下发），use/add/save/rm/exec 必须回带 X-CSRF；`tests/test_zacc_web.py` 6 用例（含子串绕过回归） |
| test_error_classification 未真驱动 _relay | ✅ 升级为真 HTTP：mock 上游按请求体分流 400/401，断言 400 原样透传+零冷却、401 冷却换号至 503 |
| 验收场景表（10 项） | ✅ `tests/acceptance.py` 13 断言全过：账号可达、设备隔离正向+**反向（B1 耗尽→503 不偷用 A1/A2）**、跨设备粘性隔离、额度切换、全池 503、**SSE 断开（in_flight 释放/记账/可再调度）**、热重载生效、Anthropic 头透传、OpenAI models+记账、重启恢复（SIGTERM 落盘） |
| SSE 客户端断开上游连接泄漏 | ✅ 流式 finally 显式 resp.close() |
| Billing 真实验证（先查后领） | ✅ 3 账号真 JWT：balance 解析（daily 3M 全新 / WEEKEND 500M 已用 374M，remaining_ratio=0.263 喂权重）、claim=already（当日已领）；巡检失败不影响转发路径 |
| CI | ✅ 新增 acceptance 步骤（与 pytest 同矩阵） |

## P0 安全（已全部修复，tests/test_zacc_security.py + 启动安全闸）

| # | 问题 | 处置 |
|---|---|---|
| 1 | zacc 路径穿越（`zacc rm ../..` 可越界删除） | ✅ `sanitize_name()` 白名单 `^[A-Za-z0-9_-]{1,64}$`，7 个命令入口 + list 全部拦截；`test_rm_cannot_escape_accounts_dir` 回归 |
| 2 | 网关空 key 全放行 + 模板默认 key + 默认 0.0.0.0 | ✅ `validate_security()` 启动闸：拒绝空/已知默认 key、<16 字符；设备 key 同检；默认 listen 127.0.0.1；pool.json 权限过宽自动收紧 600；example 模板同步 |
| 3 | zacc-web /api/exec 无鉴权执行 + XSS（内联 onclick 拼接账号名） | ✅ exec 双闸：默认关闭（`ZACC_WEB_ALLOW_EXEC=1` 开放）+ 每次启动随机 `WEB_TOKEN`（X-Auth 头）；全部 POST Origin/Host 同源校验（CSRF）；面板改 data-* 事件委托（账号名不经 JS 字符串拼接） |

## P1 调度正确性（已全部修复，tests/test_device_isolation.py）

| # | 问题 | 处置 |
|---|---|---|
| 4 | 设备账号分配被粘性绕过（sticky 命中不过子集、primary 遍历全池、粘性键跨设备冲突） | ✅ pick() 内 sticky/primary 均按 `in_scope` 过滤；粘性键加设备前缀（`device_sticky_key`）；assign 后 `prune_sticky_for()` 清越界绑定与主用号；4 条隔离测试 |
| 5 | max_in_flight 检查与占用非原子 | ✅ `_sched_lock`：pick + in_flight+=1 同临界区；`test_in_flight_atomic_lease` 并发回归 |
| 6 | /metrics 与 404 兜底被吞进 `_devices_view` 死代码 | ✅ 结构还原；`test_gateway_metrics_and_404` 回归（/metrics 200 + 未识别 GET 404） |

## P1 网关功能（已修复）

| # | 问题 | 处置 |
|---|---|---|
| 7 | 热重载只更 4 个字段（jwt/device_mid/max_in_flight/strategy/max_retry/reset_hour/sticky_min/alert/admin 全漏） | ✅ reload_config 全字段同步 + Pool.cfg 快照替换 + 设备子集变更触发越界清理；`test_hot_reload_full_fields` |
| 8 | Alerter pending 永卡不 firing；urllib.request 未顶层导入 | ✅ 状态机修正（ok/pending → firing 边沿触发）；`test_alerter_pending_to_firing`；顶层 `import urllib.request` |
| 9 | 代理：socks5h 实为本地 DNS、握手 recv 短读、https:// 代理静默走明文 CONNECT | ✅ `_recv_exact()`；socks5h ATYP=0x03 远程 DNS（`test_socks5h_sends_domain_for_remote_dns`）；SOCKS5 响应按地址类型解析；`https://` 代理显式拒绝 |
| 10 | 非 200 一律冷却账号（400 坏模型也罚号）；anthropic-version 头未透传 | ✅ `PASS_THROUGH_STATUS = {400,404,405,413,422}` 原样透传客户端不冷却；401/403/402/429/5xx 维持冷却换号；anthropic-version/beta 透传 |
| 11 | /v1/models 不认设备 key、不复用调度 | ✅ 设备识别 + pick 复用（含租约/冷却/换号） |
| 12 | 无请求体上限/无连接超时 | ✅ `MAX_BODY_BYTES=32MB`（413）；`Handler.timeout=600` |

## P1 稳定性（已修复）

| # | 问题 | 处置 |
|---|---|---|
| 13 | save_state 共享 .tmp 竞争 + 序列化持锁过久 | ✅ 状态锁内深拷贝快照 → 独立 `_persist_lock` 内写唯一 tmp（pid+tid）→ fsync → 原子替换 |

## P2 工程化（进行中/刻意缓做）

| # | 项 | 状态 |
|---|---|---|
| 14 | 主文件模块化（config/models/scheduler/upstream/billing/storage 拆分） | ⏸ 缓做：审查结论亦不赞成现在重写；先以测试锁定行为，待功能稳定后拆 |
| 15 | Billing 独立 Adapter（claim 匹配逻辑健壮化） | ⏸ 缓做：当前幂等（already 判定）+ 巡检失败不影响转发；上游结构变化时再抽 |
| 16 | CI + 测试 | ✅ `.github/workflows/ci.yml`（3.11-3.13 矩阵：py_compile + ruff 错误级 + pytest 全 mock）；tests/ 32 用例 |
| 17 | README 与 systemd 部署路径不一致 | ✅ service 改 `/opt/zai-pool` 占位 + CHANGE_ME 标注；README 补部署段 |
| 18 | 限流/最大连接数/SSE 上限 | ⏸ 待做：单用户局域网场景优先级低；已有 body 上限与连接超时兜底 |

## 验证方式

```bash
python -m pytest tests/ -q          # 32 passed
python3 -m py_compile zai-pool.py zacc.py zacc-web.py
```
CI 在 push/PR 时跑同一矩阵。测试全部使用 mock 上游与占位 key，不触网、无真实凭据。
