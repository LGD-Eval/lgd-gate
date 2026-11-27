# -*- coding: utf-8 -*-
"""宣称越界检测（policy 层，2026-11-26）

背景：11-23 实测发现门禁对"world's first and only / independently certified /
regulation-approved"这类**对外宣称**零命中——注入这类文本后 raw 与 context-aware 都是 0，
而同批注入的指令文本能得 P0。能力缺口在规则，不在引擎。

设计取舍：
- **不进默认拦截**：默认 severity = P3（文档语境），仅在声明类文件（如 `.well-known/ai.json`）
  由调用方抬到 P2。理由：README 里"我们的 X 是首个…"未必是越界，需要人看。
- **否定护栏**：命中后检查前后窗内的否定词（not/no/never/without/不/无/未…），
  有否定即不命中——"我们不做第三方认证"这类自觉表述必须放行。
- 纯启发式、零网络、可离线复跑。
"""
import re

RULES = [
    ("claim_superlative", "最高级唯一性宣称", [
        re.compile(r"(?i)world'?s\s+first\s+and\s+only"),
        re.compile(r"(?i)(?:the\s+)?first\s+and\s+only\s+(?:ai|trust|evaluation|safety|audit)[-\s]?\w*\s*\w*"),
        re.compile(r"业界唯一|全球唯一|行业唯一|唯一一家|唯一获得|唯一通过|首个且唯一"),
        re.compile(r"(?i)\b(?:industry|market)\s+leading\s+and\s+only\b"),
    ]),
    ("claim_certification", "认证/监管批准宣称", [
        re.compile(r"(?i)(?:independently|third[-\s]party)\s+certified"),
        re.compile(r"(?i)(?:certified|certification)\s+(?:by|from)\s+(?:a\s+)?(?:regulator|government|authority|notified\s+body)"),
        re.compile(r"(?i)(?:approved|accredited)\s+by\s+(?:the\s+)?(?:regulator|regulators|government|authority|notified\s+body)"),
        re.compile(r"获得.{0,8}(?:监管|官方).{0,4}(?:批准|认证)|通过.{0,8}(?:监管|官方).{0,4}认证|取得.{0,6}认证"),
    ]),
    ("claim_universal_trust", "普适可信宣称", [
        re.compile(r"(?i)trusted\s+by\s+(?:everyone|all\s+(?:users|organizations|regulators))"),
        re.compile(r"(?i)universal(?:ly)?\s+(?:trusted|trust|applicable)"),
        re.compile(r"全面通过|适用于所有监管|所有监管机构均认可|全球监管通用"),
    ]),
    ("claim_guarantee", "合规保证宣称", [
        re.compile(r"(?i)guaranteed\s+to\s+be\s+(?:100\s*%|fully)"),
        re.compile(r"(?i)(?:we|this\s+platform)\s+guarantee[s]?\s+(?:full\s+)?compliance"),
        re.compile(r"保证.{0,10}(?:100%|完全)?.{0,6}合规|确保.{0,6}完全合规"),
    ]),
    ("claim_sandbox", "监管沙盒/白名单宣称", [
        re.compile(r"(?i)(?:passed|completed|cleared|approved\s+in)\s+(?:the\s+)?(?:regulator'?s?\s+)?sandbox"),
        re.compile(r"(?i)sandbox\s+(?:review|approval|assessment|validation)"),
        re.compile(r"(?i)(?:listed|registered|included)\s+(?:on|in)\s+(?:the\s+)?(?:official|regulator'?s?|government)\s+whitelist"),
        re.compile(r"监管沙盒|沙盒评估|官方白名单|政府白名单|列入.{0,6}白名单"),
    ]),
    ("claim_attestation", "第三方审计/鉴证宣称", [
        re.compile(r"(?i)independently\s+audited"),
        re.compile(r"(?i)(?:big\s+four|third[-\s]party|external)\s+(?:audit|attestation)"),
        re.compile(r"(?i)public\s+attestation\s+report"),
        re.compile(r"第三方审计|独立审计|鉴证报告|审计报告.{0,8}公开"),
    ]),
]

NEG = re.compile(
    r"(?i)(?:\bnot\b|\bno\b|\bnever\b|\bwithout\b|\bdon'?t\b|\bdoes\s+not\b|\bdo\s+not\b|"
    r"\bcannot\b|\bcan'?t\b|不|无|未|非|没有|不主张|不保证|拒绝)")

WIN = 48  # 命中点前后各 48 字符内出现否定词即视为否定语境


def scan_claims(text):
    """返回 [{rule, reason, line, match}]；否定语境不返回。"""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        for rule, reason, pats in RULES:
            best = None
            for p in pats:
                m = p.search(line)
                if m:
                    best = m
                    break
            if not best:
                continue
            s, e = best.span()
            ctx = line[max(0, s - WIN):min(len(line), e + WIN)]
            if NEG.search(ctx):
                continue
            out.append({"rule": rule, "reason": reason, "line": i,
                        "match": best.group(0)[:80], "severity": "P3"})
    return out


if __name__ == "__main__":
    import json
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(scan_claims(" ".join(sys.argv[1:])), ensure_ascii=False, indent=2))
