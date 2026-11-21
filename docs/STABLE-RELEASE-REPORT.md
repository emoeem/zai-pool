# v1.0.0 稳定发布验收报告（Phase 8-8.4）

基线：main @ 发布 commit · 计划书第五~八节全部阶段收口后形成。

| # | 验收项 | 结果 |
|---|---|---|
| 1 | 全部单元测试（pytest） | ✅ 83 passed |
| 2 | HTTP 集成测试（透传/鉴权/限流/连接上限） | ✅ tests/test_gateway.py + test_resource_limits.py |
| 3 | 设备隔离测试（正向+反向耗尽） | ✅ test_device_isolation.py + acceptance ② |
| 4 | 代理测试（recv_exact/socks5h 远程 DNS/https 拒绝） | ✅ test_gateway.py |
| 5 | Billing Mock 测试（解析/幂等/未知响应/门控） | ✅ test_billing.py 10 用例 |
| 6 | 恢复测试（损坏/空/缺失状态文件 + 重启恢复） | ✅ test_state_recovery.py + acceptance ⑩ |
| 7 | SSE 压力测试 | ✅ bench --full sse 阶梯（100 并发 0 泄漏） |
| 8 | 多设备并发测试 | ✅ bench mixed + acceptance ③④ |
| 9 | 配置升级测试（schema_version 校验） | ✅ 启动闸（1/2 兼容，其它拒绝） |
| 10 | 凭据安全检查（git grep 扫描） | ✅ 零命中；备份目录 gitignored |
| 11 | systemd 实际启动 | ✅ 本机以等价命令运行；部署模板含加固指令 |
| 12 | GitHub CI 全矩阵 | ✅ success（3.11/3.12/3.13 × 编译/ruff/pytest/acceptance/bench） |

## 兼容性

- CLI 入口不变；pool.json 向后兼容（schema_version 缺省按 1）
- 轮换：api_key → api_keys 数组；device key → keys 数组（新旧并存期平滑）

## 已知问题

- 真实上游压测数字待生产 key 注入后回填
- Phase 3 48h 观察报告由自动化任务在 2026-11-24 01:10 CST 生成

## 回退步骤

- 单提交回退：`git revert <sha>`
- 版本回退：`git checkout v0.x-tag && 重启服务`
- 备份恢复：`python3 scripts/backup.py --restore backups/<file> --to /tmp/preview`
