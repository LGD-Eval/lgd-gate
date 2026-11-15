"""授权记录校验的回归测试。

这一层存在的理由：`authorization_status` 长期是个常量 NOT_GRANTED —— 没有授予路径，
也没有"谁授予了什么"的记录格式，等于说"不授权"这件事无法被审计。
本模块补的是记录格式；**评测器依然不读它**（授权与评测必须由两条命令分别裁决）。
"""
import datetime as dt
import json

import pytest

import authorization_record as ar

_TREE = "a" * 64
_TREE2 = "b" * 64


def _rec(**kw):
    base = dict(grantor="Steven Zhao", subject=_TREE, scope="production deploy: skill-x",
                days=90, provenance="maintainer_self", evidence=[],
                justification="low-risk static-only skill, reviewed by hand")
    base.update(kw)
    return ar.new_record(**base)


def test_valid_record_passes():
    ok, problems = ar.validate(_rec())
    assert ok, problems


def test_third_party_without_evidence_is_rejected():
    """自称第三方复核却拿不出任何依据——这正是审计要禁止的那句话。"""
    ok, problems = ar.validate(_rec(provenance="third_party", evidence=[],
                                    justification=""))
    assert not ok
    assert any("第三方" in p for p in problems), problems


def test_third_party_with_evidence_passes():
    ok, problems = ar.validate(_rec(provenance="third_party",
                                    evidence=["https://example.org/review/123"],
                                    justification=""))
    assert ok, problems


def test_self_authorization_requires_justification():
    ok, problems = ar.validate(_rec(justification=""))
    assert not ok
    assert any("justification" in p for p in problems)


@pytest.mark.parametrize("grantor", ["auto", "BOT", "ci", "system", "none"])
def test_non_person_grantor_rejected(grantor):
    ok, problems = ar.validate(_rec(grantor=grantor))
    assert not ok
    assert any("无法承担后果" in p for p in problems), problems


def test_expired_record_is_invalid_as_of_later_date():
    rec = _rec(now=dt.date(2026, 1, 1), days=10)
    later = dt.date(2026, 2, 1)
    ok, problems = ar.validate(rec, now=later)
    assert not ok
    assert any("已过期" in p for p in problems), problems


def test_expiry_must_be_after_grant():
    rec = _rec(days=0)
    ok, problems = ar.validate(rec)
    assert not ok
    assert any("晚于" in p for p in problems), problems


def test_record_for_a_different_tree_is_rejected():
    """记录只对某一棵树成立；换个目录就能复用，那授权就没有意义。"""
    ok, problems = ar.validate(_rec(), tree=_TREE2)
    assert not ok
    assert any("另一棵树" in p for p in problems), problems


def test_empty_scope_rejected():
    ok, problems = ar.validate(_rec(scope="   "))
    assert not ok
    assert any("scope" in p for p in problems), problems


def test_evaluator_does_not_read_authorization_records():
    """结构性约束：评测器不得读取授权记录，否则又回到"打分即发证"。"""
    body = open("evaluate.py", encoding="utf-8").read()
    for needle in ("authorization_record", "authorization.json", "authorization_record.py"):
        assert needle not in body, "evaluate.py 引用了 %s —— 授权必须由另一条命令裁决" % needle


def test_accepts_the_fingerprint_format_from_evidence_json():
    """--evidence-json 的 fingerprint 是 "sha256:<hex>"，记录必须能吃下这个写法。"""
    rec = _rec(subject="sha256:" + _TREE)
    ok, problems = ar.validate(rec, tree="sha256:" + _TREE)
    assert ok, problems
