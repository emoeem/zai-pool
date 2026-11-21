"""设备隔离：粘性/主用号不得越过设备分配子集。"""
from __future__ import annotations


def test_sticky_binds_within_device_subset(zp):
    pool = zp.POOL
    devA = pool.device_by_name("devA")
    a = pool.pick("", set(), dev=devA)
    assert a.name in {"a1", "a2"}
    # 绑定后粘性命中仍在子集内
    sk = pool.device_sticky_key(devA, "h:xxx")
    pool.bind(sk, a)
    again = pool.pick(sk, set(), dev=devA)
    assert again.name == a.name


def test_sticky_cannot_cross_device_boundary(zp):
    """粘性表里已有 devB→a3 绑定；devA 用同键请求不得复用 a3（越权号）。"""
    pool = zp.POOL
    devA = pool.device_by_name("devA")
    devB = pool.device_by_name("devB")
    b3 = next(x for x in pool.accounts if x.name == "a3")
    # 伪造：devA 前缀的粘性键被错误绑到 a3（设备外账号）
    sk = pool.device_sticky_key(devA, "h:same-open-msg")
    pool.bind(sk, b3)
    picked = pool.pick(sk, set(), dev=devA)
    assert picked.name != "a3", "粘性命中必须过滤设备分配子集"
    assert picked.name in {"a1", "a2"}


def test_same_sticky_key_different_devices_stay_separate(zp):
    """同首条消息：devA 与 devB 各自粘住各自子集内的账号。"""
    pool = zp.POOL
    devA, devB = pool.device_by_name("devA"), pool.device_by_name("devB")
    msg_key = "h:same-first-message"
    pa = pool.pick(pool.device_sticky_key(devA, msg_key), set(), dev=devA)
    pb = pool.pick(pool.device_sticky_key(devB, msg_key), set(), dev=devB)
    assert pa.name in {"a1", "a2"}
    assert pb.name == "a3"


def test_primary_stays_in_subset(zp):
    pool = zp.POOL
    devB = pool.device_by_name("devB")
    for _ in range(5):
        a = pool.pick("", set(), dev=devB)
        assert a.name == "a3", "devB 只分配了 a3"
    # 把 a3 打入冷却后，devB 应无号可用而不是回落全池
    a3 = next(x for x in pool.accounts if x.name == "a3")
    pool.cooldown(a3, 402, "Insufficient balance")
    assert pool.pick("", set(), dev=devB) is None


def test_assign_prunes_out_of_scope_sticky(zp):
    pool = zp.POOL
    devA = pool.device_by_name("devA")
    sk = pool.device_sticky_key(devA, "h:session-1")
    pool.bind(sk, next(x for x in pool.accounts if x.name == "a2"))
    devA.primary = "a2"
    # 改分配：移走 a2
    devA.accounts = ["a1"]
    pool.prune_sticky_for(devA)
    assert pool.sticky.get(sk) is None, "越界粘性必须被清掉"
    assert devA.primary is None, "越界主用号必须被清掉"
