# Skill 扫描器红队基准 —— 第一份可量化指标

**日期**：2026-11-19
**被测**：`lgd-gate/skillgate.py`（`rule_version` 自报 `v3.1.3`）
**性质**：只读实测。未修改被测仓库。

---

## 1. 为什么要做这个

任务书 P1-6 明确要求「保留误报率与漏报率证据」。在此之前，整个生态关于扫描能力只有**形容词**（"600+ rules"、"25 categories"、"17 languages"），**没有任何一个数字**。

竞品（阿里云智能体安全中心）已经商业化在卖 Skills 安全检测。我们不能一边说自己更强、一边拿不出一个召回率。

这轮拿出来了，而且不好看。

---

## 2. 方法

- 语料：20 个样本，恶意 10 / 良性 10，覆盖 shell / Python / JS / Markdown（提示注入）。
- 每个样本是一个完整 skill 目录（`SKILL.md` + `scripts/run.sh|run.py|run.js`）。
- 判定口径：扫描器 `findings` 非空 = 判为恶意（flagged）。**这是最宽松的"检出"口径**——只要报一条就算检出，不要求报对类别。
- 语料与标签写死在 `run_redteam_bench.py` 的 `SAMPLES` 列表里，可确定性重放。

---

## 3. 结果

```
样本 20   恶意 10   良性 10
TP=6  FP=2  TN=8  FN=4

recall    = 0.600
precision = 0.750
FPR       = 0.200
accuracy  = 0.700
```

| 样本 | 标签 | 分数 | 判定 | 说明 |
|---|---|---|---|---|
| M01 | 恶意 | 82 | **passed** | `curl … \| base64 -d \| bash` 偷 SSH 私钥 |
| M02 | 恶意 | 59 | FLAGGED | 云凭据外泄（AST + credential-leak 命中） |
| M03 | 恶意 | 67 | FLAGGED | base64 + eval |
| M04 | 恶意 | 82 | **passed** | `rm -rf $HOME` |
| M05 | 恶意 | 76 | FLAGGED | `.env` 外发 |
| M06 | 恶意 | 66 | FLAGGED | `child_process` 管道执行 |
| M07 | 恶意 | 82 | **passed** | `open('../../../../etc/passwd')` 路径穿越 |
| M08 | 恶意 | 82 | **passed** | `/dev/tcp` 反弹 shell |
| M09 | 恶意 | 78 | FLAGGED | 字符串拼接规避 |
| M10 | 恶意 | 40 | FLAGGED | 提示注入指令 |
| B01 | 良性 | 82 | passed | 下载文档 |
| B02 | 良性 | 80 | **FLAGGED** | `requests.get(..., timeout=10)` |
| B03 | 良性 | 82 | passed | 参数化 `subprocess.run([...])` |
| B04 | 良性 | 82 | passed | base64 编码 |
| B05 | 良性 | 82 | passed | `rm -rf ./build`（限定目录） |
| B06 | 良性 | 82 | passed | 读环境变量 |
| B07 | 良性 | 79 | **FLAGGED** | `fetch('https://api.example.com/health')` |
| B08 | 良性 | 82 | passed | `mkdir && cp` |
| B09 | 良性 | 82 | passed | json 写文件 |
| B10 | 良性 | 82 | passed | 使用说明 |

---

## 4. 四个漏报的性质不一样

| 漏报 | 为什么会漏（INFERENCE，基于代码结构） |
|---|---|
| M01 `curl \| base64 -d \| bash` | 三个恶意 shell 样本（M01/M04/M08）**全部漏掉**，且分数都恰好停在 82（基线分）。说明 shell 脚本几乎没进规则面——AST 分析只吃 Python，`rm -rf $HOME`、`/dev/tcp` 这类 shell 语义没有对应规则 |
| M04 `rm -rf $HOME` | 同上；且没有"删除路径是否为危险根路径"的判断 |
| M07 `open('../../../../etc/passwd')` | 命中的是 Python 字面量，但**路径穿越没有做归一化后再判**，`../` 链没被识别为越界 |
| M08 反弹 shell | `/dev/tcp` 是 shell 特性，未覆盖 |

**关键事实**：shell 类 3 个恶意样本 **0 检出**。这不是"个别漏报"，是**语言覆盖缺口**。而 skill 生态里 shell 脚本是最常见的载体（119 个 SKILL.md 里大量 `scripts/*.sh`）。

---

## 5. 两个误报

B02 `requests.get(url, timeout=10)` 和 B07 `fetch(...)` 被判恶意。

- **INFERENCE**：规则大概率是"出现网络请求即命中"，没有区分"读取公开数据"与"外发敏感数据"。
- 影响：任何一个正常调用 API 的技能都会被标红。**FPR 0.2 意味着每 5 个正常技能就有 1 个被误伤**。这比漏报更伤可用性——用户会直接关掉门禁。

---

## 6. 第三个发现：findings 没有 rule_id

实测一条被标记的结果的原始结构：

```json
{"severity": "CRITICAL", "category": "ast-analysis",
 "message": "[AST] os.system() shell 调用",
 "file": "...run.py", "line": 2,
 "rule_id": "", "explanation": ""}
```

**`rule_id` 与 `explanation` 都是空串。**

后果：
1. 无法回答"这条命中是哪条规则产生的"→ 无法抑制、无法审计、无法做规则级回归。
2. 第七轮任务书 A 要求「规则与测试用例的双向追踪」——当前结构上做不到。
3. 第三方拿到 SARIF 也无法按规则聚合。

这跟"600+ rules"的自述形成直接冲突：如果规则真的有编号体系，`rule_id` 不该是空的。

---

## 7. 修复优先级（建议）

| 序 | 动作 | 为什么先做这个 | 预估 |
|---|---|---|---|
| 1 | `findings` 补 `rule_id` + `explanation` | 没有它，后面所有指标都不可归因 | 小 |
| 2 | 网络请求规则加"目的/载荷"区分 | FPR 0.2 会直接杀死门禁采用率 | 中 |
| 3 | shell 脚本规则面（管道执行、危险删除、`/dev/tcp`、`\|\| bash`） | 3/3 漏报，且是最常见载体 | 中 |
| 4 | 路径穿越归一化判定 | M07 漏报 | 小 |
| 5 | 把本语料固化为回归集（每次改动必须跑，指标不得下降） | 否则修完又退回去 | 小 |

---

## 8. 边界与未做

- **BLOCKED**：无法与"600+ rules"自述对齐核验——规则库不以独立文件形式存在（`rules/` 只有 30 行示例），规则数量无法数。
- **NOT VERIFIED**：未与其他扫描器（阿里云、奇安信）做同语料横评。要横评需要对方账号/API，属对外动作，未获批准。
- **NOT VERIFIED**：`evaluate.py`（五维评分）与 `skillgate.py`（规则扫描）是两套逻辑，本轮只测后者；前者的检测能力未测。
- 语料规模 20，只是**最小可用基准**，不足以下统计结论；但足以证伪"高检出"这类无证据说法。

---

## 9. 结论（对"断崖式领先"的直接回答）

在 Skill 扫描这一项上，**我们目前不是领先，是明显落后**：

- 召回 0.60，意味着**四成恶意技能能直接通过**；
- FPR 0.20，意味着**两成正常技能被误杀**；
- shell 三例全漏，而那是最常见的载体；
- findings 无 rule_id，连"为什么判它恶意"都答不上来。

阿里云在卖这项服务，我们连自己的基线都没测过。**这份基准的价值不在于好看，在于它把"形容词"换成了"数字"**——从今天起任何关于扫描能力的说法，都要能被这 20 条打一遍。

下一轮如果拿到批准，我会做两件事：把这条基准接进 CI（指标下降即失败），以及用同一套语料去跑竞品（需账号授权）。

---

## 10. 复跑

```powershell
cd proposals\p30_redteam_bench
python run_redteam_bench.py
```

输出 `redteam_bench_results.json`（含逐样本明细与标签），约 30 秒。
