"""action.yml 与评测器的口径一致性守卫。

缘由：action.yml 里曾有一份独立的等级映射（>=60 C / >=40 D / 其余 F），
与 evaluate.py 的 grade_for **当时恰好同表**（实测 13 个边界分数逐点相等）。
同表不等于同源：评测器改一次刻度，Action 这份不动，CI 就会发出与工具不一致的等级，
而且没有任何测试会红。

判据只有一条：等级必须来自评测器的输出，不能二次计算。
"""
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTION = os.path.join(HERE, "action.yml")
EVAL = os.path.join(HERE, "evaluate.py")


def _action() -> str:
    return open(ACTION, encoding="utf-8").read()


def test_grade_is_parsed_not_recomputed():
    body = _action()
    assert "GRADE=$(awk" in body, "等级必须从评测器输出里取"
    # 不得再出现按分数二次判断等级的阶梯（这正是分叉的形态）
    assert not re.search(r'if\s+\[\s+"?\$SCORE"?\s+-ge\s+\d+\s*\]\s*;\s*then\s+GRADE=', body), (
        "action.yml 又在重算等级了：等级只能有一个来源"
    )


def test_action_hardcodes_no_grade_letters():
    """Action 不得自己写出任何等级字母（那必然是第二份刻度）。

    等级只能来自评测器输出行；这里只允许 GRADE=$(...) 这种取值写法，
    不允许 GRADE="A+/A/B/C/D/F" 这类赋值。
    """
    body = _action()
    for grade in ("A+", "A", "B", "C", "D", "F"):
        assert 'GRADE="%s"' % grade not in body, "action.yml 里出现了写死的等级 %s" % grade
    assert "GRADE=$(awk" in body


def test_threshold_default_is_documented_value():
    """默认门槛 90 与 README/文档口径一致；改动必须是显式决定（A-17a 未获批）。"""
    body = _action()
    m = re.search(r"threshold:\s*\n(?:.*\n)*?\s+default: '(\d+)'", body)
    assert m and m.group(1) == "90", "默认门槛被改动：%r" % (m.group(1) if m else None)


def test_action_runs_the_pinned_evaluator():
    """Marketplace 跑的就是仓根 evaluate.py（与正典逐字节同源）。"""
    assert 'github.action_path }}/evaluate.py' in _action()
