# -*- coding: utf-8 -*-
"""P0-2 提案：Evaluation / Risk / Authorization 三权分离的原型（stdlib-only）

设计要点（对应当前缺陷「评分直接授予执行权限」）：
  1. Evaluation（E）只产出可复算的度量：score / grade / dimensions。
  2. Risk（R）只产出可枚举的发现：findings（severity + unresolved）。
  3. Authorization（A）只产出显式裁决：GRANTED / NOT_GRANTED / UNKNOWN / INCOMPLETE。
     - 默认 NOT_GRANTED（白名单式：不满足全部条件就不给）。
     - 分数**从不**参与授权判定；分数只作为 A 的输入证据之一被记录。
     - 任一条 unresolved CRITICAL/HIGH → NOT_GRANTED（分数再高也不行）。
     - 评测不完整 → INCOMPLETE（fail-closed）。
     - 证据不可核验 / 规则版本未知 → UNKNOWN（fail-closed）。
     - 签发者与评测者必须不同（职责分离），否则 NOT_GRANTED。
     - 无显式策略匹配 → NOT_GRANTED。

本文件为**审计产物/提案**，未进入任何仓库；须 Steven 批准后方可移植。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    GRANTED = "GRANTED"
    NOT_GRANTED = "NOT_GRANTED"
    UNKNOWN = "UNKNOWN"
    INCOMPLETE = "INCOMPLETE"


BLOCKING = ("CRITICAL", "HIGH")


@dataclass
class Evaluation:
    """度量层：可复算、可重放，不产生权限。"""
    skill: str
    score: int
    grade: str
    dimensions: dict
    rule_version: str | None
    evidence_sha256: str | None
    complete: bool = True
    evaluator: str = "lgd-gate"


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    resolved: bool = False


@dataclass
class Risk:
    """风险层：只描述发现，不下结论。"""
    findings: list = field(default_factory=list)

    @property
    def blocking_unresolved(self):
        return [f for f in self.findings
                if f.severity in BLOCKING and not f.resolved]

    @property
    def score_band(self):
        """风险分带，与 Trust Score 无关，单独可读。"""
        if self.blocking_unresolved:
            return "high"
        med = [f for f in self.findings if f.severity == "MEDIUM" and not f.resolved]
        return "medium" if med else "low"


def decide(ev: Evaluation, risk: Risk, policy: dict | None, issuer: str) -> dict:
    """授权层：fail-closed 的单一出口。"""
    reasons = []
    evidence = {
        "skill": ev.skill,
        "score": ev.score,          # 仅记录，不参与判定
        "grade": ev.grade,
        "risk_band": risk.score_band,
        "rule_version": ev.rule_version,
        "evidence_sha256": ev.evidence_sha256,
        "blocking": [f.rule for f in risk.blocking_unresolved][:8],
    }

    # 1) 证据/规则不可知 → UNKNOWN（不是"通过"）
    if not ev.evidence_sha256 or not ev.rule_version:
        reasons.append("evidence or rule_version missing -> cannot be verified")
        return _out(Decision.UNKNOWN, reasons, evidence, issuer)

    # 2) 评测不完整 → INCOMPLETE
    if not ev.complete:
        reasons.append("evaluation incomplete (missing dimensions or data)")
        return _out(Decision.INCOMPLETE, reasons, evidence, issuer)

    # 3) 无策略 → 默认拒绝
    if not policy:
        reasons.append("no authorization policy matched; default is deny")
        return _out(Decision.NOT_GRANTED, reasons, evidence, issuer)

    # 4) 职责分离：评测者不得自签
    if issuer == ev.evaluator:
        reasons.append("separation of duties violated: evaluator issued the grant")
        return _out(Decision.NOT_GRANTED, reasons, evidence, issuer)

    # 5) 阻断级未解决发现
    if risk.blocking_unresolved:
        reasons.append("%d unresolved CRITICAL/HIGH finding(s)" % len(risk.blocking_unresolved))
        return _out(Decision.NOT_GRANTED, reasons, evidence, issuer)

    # 6) 策略阈值（作为策略条件，而非"分数即权限"）
    if ev.score < int(policy.get("min_score", 101)):
        reasons.append("score %d below policy min_score %s" % (ev.score, policy.get("min_score")))
        return _out(Decision.NOT_GRANTED, reasons, evidence, issuer)

    if policy.get("require_resolved_all") and any(not f.resolved for f in risk.findings):
        reasons.append("policy requires every finding resolved")
        return _out(Decision.NOT_GRANTED, reasons, evidence, issuer)

    reasons.append("all policy conditions satisfied")
    return _out(Decision.GRANTED, reasons, evidence, issuer, scope=policy.get("scope"))


def _out(decision, reasons, evidence, issuer, scope=None):
    payload = {
        "decision": decision.value,
        "scope": scope,
        "issuer": issuer,
        "reasons": reasons,
        "evidence": evidence,
        "policy_version": (evidence.get("rule_version")),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    payload["decision_sha256"] = digest
    return payload
