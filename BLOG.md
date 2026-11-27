# Why We Built LGD-Gate: The Missing Third-Party Evaluator for AI Agent Skills

> Published: 2026-10-28
> By: LGD-Eval — Independent Third-Party Agent Skill Evaluation

---

## The Problem

AI agents are taking over. We now install "skills" — code that runs with our permissions, reads our files, and talks to our APIs.

But here's the problem:

- **There is no standard way to evaluate them.**
- **No independent third party to audit them.**
- **No evidence that they are actually safe.**

We have npm audit, we have bandit, we have snyk — but for the new world of **agent skills**, there is nothing.

---

## Our Solution: LGD-Gate

LGD-Gate is an open-source, third-party evaluator for AI Agent Skills.

It scans, scores, and gates any Claude/Cursor/Codex skill **before you install it**.

### 18 Dimensions of Evaluation:

1. Structure completeness
2. Security checks
3. Numerical honesty (we learned from third-party evaluation!)
4. Bug fix verification
5. Hygiene checks
6. AI-friendliness
7. LGD ecosystem interlink
8. LGD three-laws audit
9. Fact consistency
10. Silent failure audit
11. Evaluation integrity
12. Loss of control
13. Harmful content / toxicity
14. HHH alignment (Helpful / Harmless / Honest)
15. Explainability
16. Maintainability
17. International compliance
18. Red team / hacker attack simulation

---

## Why Independent?

We are a **three-way separation** organization:

| Role | Who | What |
|------|-----|------|
| Theory | zhaoxinghua09-cell | LGD theory, standards |
| Product | stevenzhao07 | MedXpert medical tools |
| **Evaluation** | **LGD-Eval** | **We evaluate everyone, including ourselves** |

We do not make the products we evaluate. We do not profit from the products we evaluate.

We are **independent**.

---

## How It Works (30 seconds)

```bash
# Scan any skill
python skillgate.py scan path/to/skill/

# Full 18-dimension evaluation
python lgd_audit.py path/to/skill/

# That's it. No API keys. No cloud. Offline.
```

---

## Why Trust Us?

1. **Evidence, not claims.** We publish our own scores and our own failures.
2. **Open source.** You can read every line of our code.
3. **Offline-first.** No data leaves your machine.
4. **Zero config.** Works out of the box.
5. **We evaluate ourselves.** We score our own tools with the same rubric.

---

## Our Track Record

We have evaluated:
- **MedXpert** — 21 medical device regulatory modules: 20 passed, 1 failed (we published the failure)
- **SkillGate** — our own basic scanner: 99/100 A+

We **publish our failures**. Because an institution that hides its problems is not authoritative.

---

## Get Started

- GitHub: https://github.com/LGD-Eval/lgd-gate
- llms.txt: https://github.com/LGD-Eval/lgd-gate/blob/main/llms.txt
- SKILL.md: https://github.com/LGD-Eval/lgd-gate/blob/main/SKILL.md

---

## Contributing

We are open source. We welcome PRs, issues, and independent audits.

- CONTRIBUTING.md: https://github.com/LGD-Eval/lgd-gate/blob/main/CONTRIBUTING.md
- GOVERNANCE.md: https://github.com/LGD-Eval/lgd-gate/blob/main/GOVERNANCE.md

---

*We do not claim authority. We prove it with evidence.*
