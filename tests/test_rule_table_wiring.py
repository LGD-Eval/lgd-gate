"""规则表接线守卫：不许再出现"表定义了、没人调用"的死规则。

背景（2026-11-15）：AUTH_PATTERNS 被发现从定义起就没有任何扫描循环读它——
"我们能检出 verify=False / CERT_NONE" 这条对外声称，背后是一张没通电的表。
同一轮静态核对又查出 EXFIL / LICENSE / QUALITY / VALIDATION 四张零引用表。

这个测试把两种状态都变成显式：接线（ACTIVE_RULE_TABLES）或声明关闭并给理由
（RULE_TABLES_DECLARED_OFF）。第三种状态——沉默的死表——直接判红。
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import skillgate  # noqa: E402

SOURCE = os.path.join(HERE, "skillgate.py")


def _table_names():
    """源码里所有 *_PATTERNS / *_HOOKS 表的名字（按 AST 看，不靠 grep）。"""
    tree = ast.parse(open(SOURCE, encoding="utf-8").read())
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and node.targets:
            t = node.targets[0]
            if isinstance(t, ast.Name) and t.id.endswith(("_PATTERNS", "_HOOKS")):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    names.add(t.id)
    return names


def _load_counts():
    tree = ast.parse(open(SOURCE, encoding="utf-8").read())
    counts = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            counts[node.id] = counts.get(node.id, 0) + 1
    return counts


def test_every_table_is_either_wired_or_declared_off():
    tables = _table_names()
    wired = set(skillgate.ACTIVE_RULE_TABLES)
    off = set(skillgate.RULE_TABLES_DECLARED_OFF)
    unaccounted = tables - wired - off
    assert not unaccounted, "以下规则表既没接线也没声明关闭: " + repr(sorted(unaccounted))


def test_wired_tables_are_actually_read():
    counts = _load_counts()
    silent = [t for t in skillgate.ACTIVE_RULE_TABLES if counts.get(t, 0) == 0]
    assert not silent, "以下表声明为已接线，但源码里没有任何读取: " + repr(silent)


def test_declared_off_tables_all_have_reasons():
    for name, reason in skillgate.RULE_TABLES_DECLARED_OFF.items():
        assert reason and len(reason) >= 15, "关闭理由过短，等于没写: " + name


def test_declared_off_tables_are_not_read():
    """声明关闭的表若又被接回来了，声明就过期了——必须同步更新。"""
    counts = _load_counts()
    revived = [t for t in skillgate.RULE_TABLES_DECLARED_OFF if counts.get(t, 0) > 0]
    assert not revived, "以下表声明关闭但已被读取，请改成接线并更新声明: " + repr(revived)


def test_exfil_rules_live_in_network_table():
    """EXFIL_PATTERNS 声明"已并入 NETWORK_PATTERNS"——得能核到。"""
    net = " ".join(p for p, _s, _m in skillgate.NETWORK_PATTERNS)
    for needle in ("post", "urlopen", "smtplib", "socket"):
        assert needle in net, "NETWORK_PATTERNS 里找不到 %s，EXFIL 的合并声明失真" % needle
