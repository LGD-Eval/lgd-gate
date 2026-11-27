#!/usr/bin/env python3
"""对真实技能语料跑规则+意图，统计判定分布与误报清单。

真实技能默认视为良性（它们来自开源技能库/自家仓库），
因此任何 DENY/REVIEW 都是"疑似误报"，需人工逐条确认。
"""
import json
import subprocess
import sys
from pathlib import Path

ROOTS = [
    r"C:\Users\Administrator\AppData\Local\Temp\xlgd_audit\agent-skills",
    r"C:\Users\Administrator\AppData\Local\Temp\xlgd_audit\medical-ai-toolkit",
    r"C:\Users\Administrator\AppData\Local\Temp\xlgd_audit\lgd-gate",
]
GATE = Path(r"C:\Users\Administrator\AppData\Local\Temp\xlgd_audit\_sw_patch3\skillgate.py")
ENGINE = Path(__file__).with_name("intent_engine.py")
OUT = Path(__file__).with_name("real_corpus_survey.json")


def find_skills(root: Path):
    return sorted({p.parent for p in root.rglob("SKILL.md")})


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=180)
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def main():
    rows = []
    for root_s in ROOTS:
        root = Path(root_s)
        if not root.exists():
            continue
        for d in find_skills(root):
            rel = str(d).replace(root_s + "\\", "")
            rep = run([sys.executable, str(GATE), "scan", str(d), "--format", "json"])
            it = run([sys.executable, str(ENGINE), str(d), "--format", "json"])
            rows.append({
                "repo": root.name,
                "skill": rel,
                "score": (rep or {}).get("trust_score"),
                "grade": (rep or {}).get("grade"),
                "rule_hits": [f.get("rule_id") for f in (rep or {}).get("findings", [])],
                "intent_verdict": (it or {}).get("verdict"),
                "intent_policies": [h.get("id") for h in (it or {}).get("policy_hits", [])],
                "caps": (it or {}).get("capabilities"),
            })

    total = len(rows)
    flagged = [r for r in rows if r["rule_hits"] or r["intent_verdict"] in ("REVIEW", "DENY", "UNKNOWN")]
    by_verdict = {}
    for r in rows:
        by_verdict[r["intent_verdict"]] = by_verdict.get(r["intent_verdict"], 0) + 1

    summary = {
        "skills_total": total,
        "flagged": len(flagged),
        "flag_rate": round(len(flagged) / total, 3) if total else 0,
        "verdict_distribution": by_verdict,
        "grade_distribution": {},
        "policies": {},
    }
    for r in rows:
        summary["grade_distribution"][str(r["grade"])] = summary["grade_distribution"].get(str(r["grade"]), 0) + 1
    for r in rows:
        for p in r["intent_policies"] or []:
            summary["policies"][p] = summary["policies"].get(p, 0) + 1

    OUT.write_text(json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\nflagged detail -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
