# -*- coding: utf-8 -*-
"""P0-2 证明用测试：分数不得授予权限；UNKNOWN/INCOMPLETE fail-closed。"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from authorization import Decision, Evaluation, Finding, Risk, decide  # noqa


def ev(score=100, complete=True, rule_version="lgd-eval/1.2", sha="a" * 64, evaluator="lgd-gate"):
    return Evaluation(skill="demo/skill", score=score, grade="A+",
                      dimensions={"security": 100, "quality": 100},
                      rule_version=rule_version, evidence_sha256=sha,
                      complete=complete, evaluator=evaluator)


POLICY = {"min_score": 80, "scope": "install-in-sandbox", "require_resolved_all": False}


class TestSeparation(unittest.TestCase):
    def test_1_perfect_score_with_critical_finding_is_denied(self):
        """分数满分 + 有未解决 CRITICAL → 必须拒绝。证明分数不授予权限。"""
        d = decide(ev(score=100), Risk([Finding("hardcoded-secret", "CRITICAL", 12)]) , POLICY, "lgd-auth")
        self.assertEqual(d["decision"], "NOT_GRANTED")
        self.assertIn("CRITICAL", " ".join(d["reasons"]))

    def test_2_perfect_score_without_policy_is_denied(self):
        """满分但无策略 → 默认拒绝（白名单式）。"""
        d = decide(ev(score=100), Risk([]), None, "lgd-auth")
        self.assertEqual(d["decision"], "NOT_GRANTED")

    def test_3_unknown_when_evidence_unverifiable(self):
        """证据哈希缺失 → UNKNOWN（fail-closed），不得降级为通过。"""
        d = decide(ev(sha=None), Risk([]), POLICY, "lgd-auth")
        self.assertEqual(d["decision"], "UNKNOWN")

    def test_4_incomplete_when_evaluation_incomplete(self):
        """评测不完整 → INCOMPLETE，而不是"部分通过"。"""
        d = decide(ev(complete=False), Risk([]), POLICY, "lgd-auth")
        self.assertEqual(d["decision"], "INCOMPLETE")

    def test_5_evaluator_cannot_self_grant(self):
        """职责分离：评测者自签 → 拒绝。"""
        d = decide(ev(), Risk([]), POLICY, "lgd-gate")
        self.assertEqual(d["decision"], "NOT_GRANTED")
        self.assertIn("separation", " ".join(d["reasons"]))

    def test_6_all_conditions_met_grants_with_scope(self):
        """全部满足才 GRANTED，且必须带 scope + 决策哈希。"""
        d = decide(ev(score=95), Risk([]), POLICY, "lgd-auth")
        self.assertEqual(d["decision"], "GRANTED")
        self.assertEqual(d["scope"], "install-in-sandbox")
        self.assertEqual(len(d["decision_sha256"]), 64)

    def test_7_score_below_policy_threshold_denied(self):
        d = decide(ev(score=70), Risk([]), POLICY, "lgd-auth")
        self.assertEqual(d["decision"], "NOT_GRANTED")

    def test_8_medium_findings_do_not_block_but_are_recorded(self):
        """MEDIUM 不阻断，但风险带必须为 medium 并被记录。"""
        d = decide(ev(score=95), Risk([Finding("eval-use", "MEDIUM", 3)],), POLICY, "lgd-auth")
        self.assertEqual(d["decision"], "GRANTED")
        self.assertEqual(d["evidence"]["risk_band"], "medium")

    def test_9_resolved_critical_does_not_block(self):
        """已解决的 CRITICAL 不阻断 —— 证明"整改后复评"路径可用。"""
        d = decide(ev(score=90), Risk([Finding("hardcoded-secret", "CRITICAL", 12, resolved=True)]) , POLICY, "lgd-auth")
        self.assertEqual(d["decision"], "GRANTED")

    def test_10_policy_requires_all_resolved(self):
        p = dict(POLICY, require_resolved_all=True)
        d = decide(ev(score=95), Risk([Finding("eval-use", "MEDIUM", 3)]), p, "lgd-auth")
        self.assertEqual(d["decision"], "NOT_GRANTED")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestSeparation)
    r = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if r.wasSuccessful() else 1)
