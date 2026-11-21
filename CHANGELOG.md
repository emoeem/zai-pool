# Changelog

所有显著变更记录于此。格式参考 Keep a Changelog；版本遵循 SemVer。

## [1.0.0] - 2026-11-22

首个稳定版本。八阶段改进计划（源码审查 → P0/P1 修复 → 生产验收 → 资源管理 → Billing 独立化 → 安全/备份/发布）全部收口。

### 新增
- 多账号网关：OpenAI/Anthropic 双协议入口，global(api.z.ai) / cn(open.bigmodel.cn) 双上游
- 设备管理：独立 key（支持数组平滑轮换）、账号分配子集、每设备用量台账、运行时改分配
- 调度：sticky-first/balanced 双策略、三因子加权、会话粘性（设备命名空间五级键）、原子并发租约
- 状态机：429 有界退避 / 402·1113 次日冷却 / 5xx 熔断 / 未知失败降权 / 双状态位，原因分解可观测
- billing/ 独立子系统：balance 巡检喂权重、每日 claim 状态机（pending→previewed→claiming→success/already/failed→verified）、幂等账本持久化、auto_claim 默认关闭
- 资源边界：BoundedServer 连接上限、SSE 独立配额、SSE 增量解析器、超时体系分离、内存令牌桶限流（全局+设备级，与上游状态机隔离）
- 可观测：Web 面板、/metrics（zaipool_* 家族）、调度统计（sticky 命中/解绑/主用号切换/切号原因）、每请求单行日志
- 运维：SIGHUP 热重载（全字段）、SIGTERM 落盘、审计 JSONL、告警三态机、备份/恢复工具（可选 Fernet 加密）、schema_version 配置校验、systemd 加固
- zacc：多账号切换/独立数据目录运行/凭据解密（keyring AES-GCM）/严格路径白名单；zacc-web 面板（严格同源 + CSRF + exec 双闸）
- 质量：pytest 83 用例 + 13 断言生产验收套件 + 压测工具（阶梯 1-100 并发）+ CI（3.11/3.12/3.13：编译/ruff/pytest/acceptance/bench 冒烟）

### 兼容性
- `python3 zai-pool.py --config pool.json` 与 zacc 全部 CLI 保持不变
- pool.json 新增 `schema_version`（1/2 兼容）、`server`、`api_keys`/`keys` 数组、`billing.auto_claim`
- 既有 pool.json / pool-state.json / zacc 档案无需迁移

### 已知限制
- zcode 客户端对话域（zcode-plan 对话端点）带签名 v4，不可第三方复刻——网关走官方 API Key 通道
- 压测基线为 mock 上游数字；真实延迟待生产 key 注入后复测
