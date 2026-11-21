# Phase 3 运行观察报告

- 状态：**观察进行中**（48 小时窗口 + 1 个完整 billing 巡检周期）
- 开始时间：（首次快照后回填）
- Git HEAD：bc72732 → 观察期起点以快照 JSONL 内 head 为准
- 账号数：5 · 设备数：4 · 策略：sticky-first
- 说明：报告由 `python3 scripts/observe.py report` 聚合 `runtime-observations.jsonl` 自动生成；
  结束后回填「异常与结论」段。

## 观察项清单（计划书 3.1）

1. 账号是否频繁发生不必要的切换（primary_switches / switch_reasons）
2. sticky 持续正确（sticky_hits / sticky_unbind）
3. 设备始终遵循账号分配（acceptance ② 已锁，运行期看 /status.devices）
4. in_flight 正常归零
5. pool-state.json 持续正确保存
6. 重启后状态正确恢复（acceptance ⑩ 已锁）
7. Billing 失败不影响 API 转发
8. 告警触发/恢复符合条件
9. 配置热重载完整生效
10. SSE 断开释放上游资源（acceptance ⑥ 已锁）
