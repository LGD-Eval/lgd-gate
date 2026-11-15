"""action.yml 与评测器的口径一致性守卫。

缘由：action.yml 里曾有一份独立的等级映射（<40 记 F），而 evaluate.py 只发
A+/A/B/C/D，从不发 F。同一个 12 分，工具说 D、Action 说 F——
"徽章/等级与实际一致"这条（G5）就没法成立。

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


def test_action_never_emits_a_grade_the_tool_cannot_emit():
    """evaluate.py 只发 A+/A/B/C/D；action.yml 不得出现 F 这个等级。"""
    tool = open(EVAL, encoding="utf-8").read()
    for grade in ("A+", "A", "B", "C", "D"):
        assert '"%s"' % grade in tool, "评测器应当能产出 %s" % grade
    body = _action()
    assert 'GRADE="F"' not in body and "F\n" not in body, "action.yml 不得发明评测器不产出的等级"


def test_threshold_default_is_documented_value():
    """默认门槛 90 与 README/文档口径一致；改动必须是显式决定（A-17a 未获批）。"""
    body = _action()
    m = re.search(r"threshold:\s*\n(?:.*\n)*?\s+default: '(\d+)'", body)
    assert m and m.group(1) == "90", "默认门槛被改动：%r" % (m.group(1) if m else None)


def test_action_runs_the_pinned_evaluator():
    """Marketplace 跑的就是仓根 evaluate.py（与正典逐字节同源）。"""
    assert 'github.action_path }}/evaluate.py' in _action()
