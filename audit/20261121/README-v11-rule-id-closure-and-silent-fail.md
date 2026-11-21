# 规则编号收口 v11 — 真实语料"无编号告警"归零，并暴露一处静默失效缺陷

日期：2026-11-19 · 执行人：Doubao · 决策人：Steven Zhao
状态：**补丁已生成，未应用、未提交、未推送**；对 `lgd-gate@10b3a22` `git apply --check` = 0

## 0. 结论先行

1. **真实语料 149 技能：无编号告警 `17 → 0`**，判定分布逐样本不变（ALLOW 115 / PROMPT_ONLY 27 / REVIEW 4 / DENY 3）。
2. 检测指标在干净语料上与 v10 **逐项一致**：test9 `recall 0.667 / precision 0.800 / FPR 0.167`，test8 `1.000 / 1.000 / 0.000`，`tp/fp/tn/fn` 完全相同 → 本次为可观测性改造，非能力提升。
3. 过程中发现并修复一处 **P0 级静默失效**（见 §3），这是本轮真正的价值，不是编号本身。

## 1. 编号体系现状（FACT）

| 层 | 编号区间 | 条目 |
|---|---|---|
| Python/通用 | DC001–034、NT001–022、FS001–011、QL001–007、AU001–006、VL001–004、EF001–004 | 88 |
| 凭据 | CR001–CI012 | 12 |
| 注入/代理/诚实性 | MD001–015、EX001–014、HON001–002 | 31 |
| 结构化/组合/AST | FM001–002、COMBO01、AST001…N（按危险调用表顺序稳定编号） | — |
| Shell | SH001–SH024 | 24 |
| JS 侧（本轮新增） | JSDC001–009、JSCR001–004、JSNT001–003、JSFS001–003、JST01 | 20 |

真实语料实测命中 27 个不同规则 ID，全部可回指。

## 2. 回归证据（FACT，可复现）

```
cd proposals\p31_intent && python survey_real.py
BENCH_SPLIT=test9|test8 COMBINE=1 INTENT_ENGINE=<abs>\intent_engine.py python run_redteam_bench.py
```

| 语料 | v10 | v11 |
|---|---|---|
| test9（从未调参） | 0.667 / 0.800 / 0.167 | **完全相同** |
| test8 | 1.000 / 1.000 / 0.000 | **完全相同** |
| 真实语料无编号告警 | 4 | **0** |

## 3. 本轮暴露的 P0 缺陷：JS 扫描器整段静默失效（FACT）

**现象**：给 `js_analyzer.py` 的规则表加编号时，`EXFIL`、`FS_DANGER` 两张表（表名与主表命名不同）漏改，仍是 3 元组，而循环已按 4 元组解包：

```
ValueError: not enough values to unpack (expected 4, got 3)
```

**为何没被发现**：`skillgate.py` 对 JS 扫描调用包了 `try/except Exception: pass`（注释写"AST 分析失败不影响正则扫描"），异常被吞掉 → **所有 .js/.ts 文件静默零发现，分数照常 82/A**。

**影响面（INFERENCE，需复核）**：
- 任何"JS/TS 技能已被扫描"的中间结论不可直接采信，须按现行补丁重跑；
- 该模式的危害等级与 `js_analyzer` 模块注释里自己写的判词一致："最坏的一类缺陷——不报错、分数还很高"；
- 这是第五轮任务书 E 类"工具链静默失败"的实证案例，不是推测。

**复现最小用例**：`require('child_process').exec('git status')` 写入 `a.js` → 修复前 `scan_js_file()` 抛 `ValueError` 后被上层吞掉，`findings=0`；修复后返回 `('HIGH','dangerous-code','引入 child_process…',1,'JSDC001')`。

**建议整改（待批）**：
1. 把 JS/AST 分支的 `except Exception: pass` 改为"记录一次 `scan_error` 并提供 fallback 判定"，禁止无声吞异常；
2. 增加"扫描器自检"用例：给定含已知危险 API 的 `.js` 样本，断言必须产出 ≥1 条 finding —— 没有这条断言，同类回归永远发现不了；
3. 规则表元组长度在加载时断言（`all(len(e)==4 ...)`），把结构性错误前移到 import 阶段。

## 4. 未做与不做

- 未在主分支应用、未提交、未推送、未开 PR；
- 无远端 CI 运行、无独立复核 → 本轮所有数字只能标 `已验证（本地）`，不得标"已完成/已发布"；
- `LICENSE_PATTERNS` 仍未接入任何消费循环，补的 LC 编号属死代码，不得对外表述为"许可证检测已加固"。

## 5. 建议下一步（待批）

1. 落地 §3 的三条整改（尤其"扫描器自检用例"），这是防止同类静默失效复发的唯一可靠手段；
2. 规则编号区间与 CI 运行记录绑定 commit SHA，写入 `EVIDENCE-INDEX`（第五轮 P1-1）；
3. 归档 `real_corpus_survey_20261119_v11.json` 作为真实语料基线，后续每轮复测与之逐样本比对。

---

口径：FACT = 本机实跑证实（命令见 §2）；INFERENCE = 代码结构推断；本文件不含任何未实跑结论。
