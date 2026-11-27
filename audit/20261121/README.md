# Audit artifacts — 2026-11-21

来源：只读审计与候选整改（XLGD 整改审计 2026-11-19 会话）
性质：**候选方案与证据，未经所有者批准，不代表已合并或已发布**
边界：本分支不修改主分支、不改许可证、不发布版本；仅提交审计产物与候选补丁

## 内容

- `README-v11-rule-id-closure-and-silent-fail.md` — 规则编号收口报告（含 JS 扫描器静默失效 P0 发现）
- `skillgate_rules_v11.patch` — skillgate/js_analyzer 规则补丁（本分支**已应用**于代码）
- `real_corpus_survey_20261119_v11.json` — 149 个真实技能扫描基线（无编号告警 = 0）
- `bench_test8_hybrid_v11c.json` / `bench_test9_hybrid_v11c.json` — 干净语料回归结果

## 可复现命令

```bash
python skillgate.py scan <skill_dir> --format json
# 干净语料回归见审计包 proposals/p30_redteam_bench/run_redteam_bench.py
```

## 已知残余

- `LICENSE_PATTERNS` 无消费循环（死代码），不得表述为许可证检测已加固
- AST/JS 分支的 `except Exception: pass` 仍会吞异常，建议改为记录 scan_error（待批）
