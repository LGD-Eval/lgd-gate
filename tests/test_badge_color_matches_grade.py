"""徽章颜色必须跟等级同表，不能另立一套分数分档。

背景（灭类不灭例）：等级是 6 档（A+ ≥90 / A ≥80 / B ≥70 / C ≥60 / D ≥40 / F），
徽章颜色原先是 5 档（≥90 / ≥75 / ≥60 / ≥40）。于是 70–79 分这一段：
等级说 B，徽章给的是 A 的颜色（79 分和 80 分看起来一模一样）。
一张徽章上同时印着"B"和"绿色"，两个符号互相打脸，外人只会看到颜色。

修法：颜色从等级查表（COLOR_FOR_GRADE），一个判断一个来源。
本测试逐分数 0..100 撑住这件事，另加一条"等级与正典评测器逐分一致"。
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import skillgate as sg
import evaluate as ev

EXPECTED = {"A+": "brightgreen", "A": "green", "B": "yellow",
            "C": "orange", "D": "red", "F": "lightgrey"}


class _R:
    def __init__(self, score):
        self.trust_score = score
        self.grade = sg.grade_from_score(score)


def _color(score):
    svg = sg.generate_badge(_R(score))
    seen = [c for c in EXPECTED.values()
            if re.search(r'fill="%s"' % c, svg)]
    return seen[0] if seen else "?"


def test_grade_scale_matches_canonical_evaluator():
    """两份等级实现必须逐分一致（正典 = evaluate.grade_for）。"""
    bad = [(s, ev.grade_for(s)[0], sg.grade_from_score(s))
           for s in range(0, 101) if ev.grade_for(s)[0] != sg.grade_from_score(s)]
    assert not bad, "等级分歧：%s" % bad[:8]


def test_badge_color_follows_grade_for_every_score():
    """0..100 每一分，徽章颜色都必须等于该分数等级的颜色。"""
    bad = []
    for s in range(0, 101):
        want = EXPECTED[sg.grade_from_score(s)]
        got = _color(s)
        if got != want:
            bad.append("%d 分(%s)：徽章 %s，应为 %s" % (s, sg.grade_from_score(s), got, want))
    assert not bad, "；".join(bad[:8])


def test_no_two_grades_share_a_color():
    """六档六色，颜色本身也要能区分等级（否则颜色等于没信息）。"""
    assert len(set(EXPECTED.values())) == 6


def test_color_table_covers_all_grades():
    assert set(sg.COLOR_FOR_GRADE) == set(EXPECTED), "COLOR_FOR_GRADE 缺档或多档"
    for g, c in EXPECTED.items():
        assert sg.COLOR_FOR_GRADE[g] == c, "%s 的颜色应为 %s" % (g, c)
