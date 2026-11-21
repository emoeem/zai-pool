"""Phase 3-3.3 调度行为统计与饥饿回归。"""
from __future__ import annotations

from collections import Counter


def test_sched_counters_sticky_hit_and_unbind(zp):
    pool = zp.POOL
    devA = pool.device_by_name("devA")
    sk = pool.device_sticky_key(devA, "h:s1")
    a = pool.pick(sk, set(), dev=devA)          # 首次：未命中（无绑定）
    assert pool.sched["sticky_unbind"] >= 0
    pool.bind(sk, a)
    pool.pick(sk, set(), dev=devA)              # 命中
    assert pool.sched["sticky_hits"] == 1
    a.cool_until = 1e18                          # 打冷却 → 解绑
    pool.pick(sk, set(), dev=devA)
    assert pool.sched["sticky_unbind"] >= 1


def test_primary_switch_counter(zp):
    pool = zp.POOL
    before = pool.sched["primary_switches"]
    pool.pick("", set())                         # 无 primary → 选中并计数
    assert pool.sched["primary_switches"] == before + 1
    pool.pick("", set())                         # 复用不计数
    assert pool.sched["primary_switches"] == before + 1


def test_switch_reason_recorded(zp):
    pool = zp.POOL
    a = pool.accounts[0]
    n = pool.sched["switch_reasons"].get("exhausted", 0)
    pool.cooldown(a, 402, "Insufficient balance")
    assert pool.sched["switch_reasons"]["exhausted"] == n + 1
    assert a.stats["fail"] == 1 and "402" in a.stats["err_last"]


def test_balanced_no_starvation(zp):
    """balanced 等权重下 200 次选号：每个账号都必须被选中（防字典序/权重饿死）。"""
    pool = zp.POOL
    pool.strategy = "balanced"
    picked = Counter()
    for i in range(200):
        for a in pool.accounts:
            a.last_picked = 0  # 关闭防惊群窗口，纯测权重分布
        x = pool.pick("", set())
        picked[x.name] += 1
    for a in pool.accounts:
        assert picked[a.name] >= 1, f"{a.name} 被饿死（200 次零选中）"
    assert min(picked.values()) >= 5, f"分布严重倾斜: {dict(picked)}"


def test_sticky_first_not_frozen_on_healthy_primary(zp):
    """sticky-first 主用号健康时不切换（冻结是特性）；主用号失效后立即恢复调度。"""
    pool = zp.POOL
    first = pool.pick("", set())
    for _ in range(10):
        assert pool.pick("", set()).name == first.name, "主用号健康必须保持粘住"
    pool.cooldown(first, 402, "Insufficient balance")
    second = pool.pick("", set())
    assert second.name != first.name, "主用号失效必须切换"
    assert pool.sched["primary_switches"] >= 1
