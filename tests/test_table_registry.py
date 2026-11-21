"""表名登记自证：元数据里的表名必须指向真表、且启用/关闭不脱钩。

`ACTIVE_RULE_TABLES` 和 `RULE_TABLES_DECLARED_OFF` 是"给人看的清单"。清单里写错一个字母，
指向的表就不存在；而引擎不会报错，只会让某一类检测悄悄失效——这正是最难发现的一类缺陷。

本文件与 test_rule_liveness.py 配套：那边管"每条规则会不会响"，这边管"每张表是不是真在跑"。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import skillgate as sg

SRC = (ROOT / "skillgate.py").read_text(encoding="utf-8")


def _src_without_registry():
    """把登记字典本身剔除：登记块里出现的表名不算"被使用"。"""
    m = re.search(r"RULE_TABLES_DECLARED_OFF = \{.*?\n\}", SRC, re.S)
    return (SRC[:m.start()] + SRC[m.end():]) if m else SRC


def _refs(name, src):
    return len(re.findall(r"\b%s\b" % re.escape(name), src))


def test_active_table_names_resolve_and_are_read():
    bad = []
    for name in sg.ACTIVE_RULE_TABLES:
        if not hasattr(sg, name):
            bad.append("启用表不存在：%s" % name)
            continue
        if not len(getattr(sg, name)):
            bad.append("启用表为空：%s" % name)
        if _refs(name, _src_without_registry()) < 2:
            bad.append("启用表登记了但没人读：%s" % name)
    assert not bad, "\n".join(bad)


def test_declared_off_tables_exist_and_are_not_read():
    bad = []
    src = _src_without_registry()
    for name in sg.RULE_TABLES_DECLARED_OFF:
        if not hasattr(sg, name):
            bad.append("声明关闭的表不存在：%s" % name)
            continue
        if _refs(name, src) != 1:
            # 只剩定义那一处；再多一处就说明它其实被读了
            bad.append("声明关闭的表仍被读取：%s（引用 %d 次）" % (name, _refs(name, src)))
    assert not bad, "\n".join(bad)


def test_registry_lists_do_not_overlap():
    overlap = set(sg.ACTIVE_RULE_TABLES) & set(sg.RULE_TABLES_DECLARED_OFF)
    assert not overlap, "同一张表既在启用清单又在关闭清单：%s" % sorted(overlap)
