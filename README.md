# zai-pool + zacc — Z.ai / GLM 多账号本地自动化工具集

个人自有账号的本地聚合与设备化管理，两个零依赖（纯 Python stdlib）工具：

## zai-pool.py — 多账号自动化网关

把 N 个自有账号聚合为一个 OpenAI/Anthropic 兼容入口，供多设备共用。

- **上游**：官方 API Key 通道
  - `global`：`api.z.ai/api/coding/paas/v4`（OpenAI 兼容）+ `api.z.ai/api/anthropic`
  - `cn`：`open.bigmodel.cn/api/coding/paas/v4` + `open.bigmodel.cn/api/anthropic`（账号 `realm: "cn"`）
- **设备管理**：`devices[]` 每设备独立 key + 账号分配子集 + 每设备用量台账；`POST /admin/devices/{name}/assign` 运行时改分配；`accounts: []` = 全池
- **额度自动化**：账号配 `zcode_jwt` + `device_mid` 后，billing 域（`zcode.z.ai/api/v1/zcode-plan`）自动巡检余额/过期（10min，确定性 jitter）+ 每日 09:00 自动 claim 当日 plan；全 remaining≤0 自动 EXHAUSTED、恢复自动 ACTIVE
- **调度**：sticky-first 主用号（设备级，失败才切换）/ balanced 双策略；三因子加权（剩余比例 + 距 expires + 闲置补偿）；Top-3 短名单等权重洗牌；会话粘性 30min（失败解绑/成功重绑/双段分配）；防惊群 100ms；in-flight 租约
- **状态机**：429 有界退避（Retry-After 对齐）/ 402·1113 冷却至次日 09:00 / 5xx 熔断 3 连败 30min×2 封顶 6h / 未知失败降权 5 次固定 10m / manual_disabled·disabled 双状态位；四截止或门不叠加
- **出口隔离（防同 IP 多账号特征）**：`accounts[].proxy`（http/socks5，含认证）或 `accounts[].sport_range`（直连源端口段，配合 dae/honk 内核层 `dport(443) && sport(a-b) -> 组名` 分流，`--honk-rules` 生成片段）
- **可观测**：`GET /` Web 面板（账号卡片/额度条/设备区/admin）、`/metrics` Prometheus、`/status` 原因分解台账、每请求单行日志（usage 缺失记 `-`）
- **工程**：pool.json 指纹热重载（SIGHUP 同效）、SIGTERM 落盘、审计 JSONL（key 指纹、启动 fail-fast）、告警 webhook 三态机（ForTicks/ClearTicks 迟滞）、systemd unit

### 快速开始

```bash
# 1. 每账号在控制台建 API Key，填 zai-pool-data/pool.json（模板 pool.example.json）
# 2. 自检（零额度消耗；--probe-chat 消耗少量额度实测出话）
python3 zai-pool.py --config zai-pool-data/pool.json --probe
# 3. 启动
python3 zai-pool.py --config zai-pool-data/pool.json
# 4. 设备接入（设备 key 或全局 key）
export OPENAI_BASE_URL=http://<主机IP>:8602/v1   OPENAI_API_KEY=<设备key>
export ANTHROPIC_BASE_URL=http://<主机IP>:8602   ANTHROPIC_API_KEY=<设备key>
# 5. systemd 常驻
sudo cp zai-pool.service /etc/systemd/system/ && sudo systemctl enable --now zai-pool
```

### 子命令

```
--probe        逐账号验 key + 出口 IP（零额度）
--probe-chat   追加真实对话冒烟
--probe-ip     仅出口 IP 校验
--honk-rules   生成 dae/honk routing 片段
--billing      手动跑一轮 billing 巡检 + claim
```

## zacc.py — ZCode 客户端多账号切换

桌面客户端不支持多开；`ZCODE_DATA_BASE_DIR` 隔离数据目录实现并行。

```
zacc add <name> [--file F]   收档（自动识别国际 zai / 国内 zai_cn，记来源 home）
zacc use <name>              切换（当前状态回写来源档案；--keep-providers 跳过）
zacc exec <name> -- <cmd>    不切换、独立数据目录运行（容器档案自动注入 HOME）
zacc ident <name>            解密账号身份（keyring AES-GCM，enc:v1/v2:os 全支持）
zacc list | current | show | where | rm
```

配套 `zacc-web.py`：本地 Web 管理面板（127.0.0.1:8600）。

## 相关文档

- dae/honk 分流：https://daeuniverse.org/zh-CN/honk/reference/routing （sport 分段为唯一干净的内核层方案）
- z.ai API：https://docs.z.ai/api-reference/introduction
- 状态机/调度模式参考：workbuddy2api（CodeBuddy 生态）、zcode2api 系列（billing 域端点）

## 安全

所有 `pool.json` / `pool-state.json` / `admin_audit.log` / 账号档案均不入库（.gitignore）；仓库只含代码与模板。仅供本人自有账号使用。
