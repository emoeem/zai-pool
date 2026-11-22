# Changelog

所有显著变更记录于此。格式参考 Keep a Changelog；版本遵循 SemVer。

## [Unreleased]

### 新增（Phase 9 JWT 对话通道接线，移植 zcode2api 实战能力）
- JWT 对话通道端到端接线：`Account.chat_via`（缺省 auto：有 api_key→apikey，仅 zcode_jwt→jwt）按账号分流 `_relay`；免费套餐（无 API Key）账号从 billing-only 升级为可对话，走 `zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages`
- 3012 三要素落地：请求时注入官方 system 提示词（`zcode-profile.json`，config 开关 `jwt_inject_profile` 默认开）+ `x-device-mid`/`x-session-id` 按 JWT user_id 恒定派生 + 完整客户端头族；`X-Aliyun-Captcha-Verify-Param` 预取
- `zai_pool/captcha.py` CaptchaManager（同步版）：client/configs 拉取（600s TTL，失败回落默认三参）+ verify_param 45s 缓存/threading 单飞 + 403 captcha 失效同号重试≤3（不冷却账号）；求解只走 playwright headed 子进程（jsdom 无头被风控判 F001，不移植）
- 模型名归一化 `MODEL_NAME_MAP`（含 glm-5.3-flash→GLM-5.3-Flash）+ `/v1/models` 在 jwt-only 池本地公布清单
- billing 域补 `/usage` 实时用量（inspect 并入 `usage` 段，进 /status 与 zaipool_billing_usage_present 指标）
- OAuth CLI 登录：`POST /admin/jwt/login_start` + `GET /admin/jwt/login_poll/{flow_id}`（ready → JWT+API Key 入 pool.json + 热重载），新账号自助入库
- JWT 过期预清：payload exp 解析，过期账号 pick 前 1h auth 冷却不入调度；热重载同步 chat_via/jwt_exp/device_mid
- 迁移脚本 `scripts/import_zcode2api.py`：zcode2api SQLite 账号库 → pool.json（dry-run 默认，--write 落盘 chmod 600）
- 修复三处 latent bug：upstream.py `import json as _json` 致官方 system 提示词/设备派生永远走静默 fallback；reload_config 对无 api_key 账号 KeyError（热重载静默失败）；billing 3001（无 device_mid 的 JWT 账号现在构造时自动派生兜底）
- 测试：92 用例全绿（新增 tests/test_jwt_relay.py 16 例，覆盖 chat_via 推导/归一化/captcha 重试与上限/402 冷却/OpenAI 协议隔离/models 本地清单/usage 解析/迁移解析）；实测流式+非流式 `/v1/messages` 200（GLM-5.3-Flash）

### 新增（Phase 6 模块化 + Phase 7 管理安全）
- `zai_pool/observability.py`：metrics 台账 + 告警三态机独立成域（POOL/LEDGER getter 注入）
- 管理端点：单账号探活 `POST /admin/accounts/{n}/probe`（零额度）、只读巡检 `/billing-check`、领取台账 `GET /billing/ledger`
- 设备禁用/启用：admin 端点 + 配置 `disabled` 真源 + 热重载同步，禁用设备请求 403 且零槽位消耗
- 备份自动化：`scripts/backup.py --encrypt` 每日 04:30 排程（Fernet 加密，密钥 600）
- 修复：Phase4 宽守卫 `/admin/` 截获 devices 路径的 404 回归

### 新增（Phase 6 渐进模块化）
- `zai_pool/` 包：core（账号/设备/调度池/状态机）、storage（状态持久化/审计，init_storage 注入式句柄）、upstream（代理隧道/源端口分流/上游请求，POOL getter 注入）三域；CLI 入口 `python3 zai-pool.py` 行为不变，71 pytest + 13 验收 + 压测冒烟全绿

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

## [Unreleased]

Phase 6 模块化 try2：try1 回滚的前置工程就位后重试，core / storage 两域抽离完成，单文件网关行为零变化。

### 变更
- 新增 `zai_pool/` 包：core 域（UPSTREAMS 族/DEFAULT_SERVER/TokenBucket/SSEUsageParser/Account/Device/Pool/状态机锁/安全闸）与 storage 域（save_state/load_state/audit/key_fp/落盘锁，`init_storage()` getter 注入）单一所有权迁入；zai-pool.py 经 re-export 回流保持调用点零改动（-619/+50 行）
- 前置工程：主文件七段域边界注释（upstream/core/storage/billing/observability/http/entry）+ 隐式共享名（MAX_BODY_BYTES/UPSTREAMS 族/BILLING_*）单一所有权标注
- 门禁：pytest 71 用例 + acceptance 13/13 全绿；剩余 upstream/billing/observability/http/entry 五域边界注释已就位待后续轮次
