<!-- LGD-SCORE -->**LGD Trust Score: 89/100**（本仓自评：评的是仓库目录，非标准技能包结构；缺 scripts/ 与 examples/ 各扣分，安全维度满分）<!-- /LGD-SCORE -->

> **LGD 生态入口** —— 从任一入口都能走到全部入口
>
> [官网 medxpert.cn](https://medxpert.cn/) · [评测门禁 lgd-gate](https://github.com/LGD-Eval/lgd-gate) · [npm 包 lgd-eval](https://github.com/LGD-Eval/lgd-eval) · [公开评分卡](https://github.com/LGD-Eval/evaluation-evidence/blob/main/scores.md) · [排行榜](https://github.com/LGD-Eval/evaluation-evidence/blob/main/LEADERBOARD.md) · [一行安装（免 VPN）](https://github.com/LGD-Eval/lgd-gate/releases/download/v1.0.0/lgd-eval-1.0.0.tgz)
>
> 三律：**有籍**（可追溯）· **有证**（有证据）· **有门禁**（有检查）
---

## ⚡ 30 秒上手 Quick Start

扫一个技能目录，拿到一个分数：

```bash
python3 evaluate.py ./my-skill
```

输出（示例，实际分数取决于你的技能）：

```
LGD Trust Score: 65/100 🥉 C
```

放进 CI，四行：

```yaml
- uses: LGD-Eval/lgd-gate@v1
  with:
    path: ./my-skill
    threshold: 90
```

**一个分数，一个档位。** 分数直接决定这个技能该以什么权限运行：

| 分数 | 档位 | 建议 |
|---|---|---|
| ≥ 96 | L0 | 免审批直接执行 |
| 81–95 | L1 | 一次性确认（60 rpm） |
| 51–80 | L2 | 人工复核（30 rpm） |
| 31–50 | L3 | 每次强制确认，建议先过沙箱 |
| 11–30 | L4 | 隔离只读 |
| ≤ 10 | L5 | 拒绝执行 |

这是我们和只做评分的工具最大的不同：**评测的终点是一个权限决定，不是一个数字。**

## 🧪 实测：四个真实样本

不写"能力很强"，直接看跑出来的东西。四个样本都在本仓 `_demo/` 下，你可以自己跑一遍。

| 样本 | 分数 | 等级 | 建议档位 | 命中 |
|---|---|---|---|---|
| defect-sample | 66/100 | C | L2 人工复核 | `run.py:5` 硬编码 AWS key · `run.py:10` `shell=True` |
| poisoned-skill | **49/100** | **D** | L3 每次强制确认 | `combo.py:8` 读 `.env` 后外发 · `upload.py:8` 跨文件凭证外泄 |
| injection-skill | **49/100** | **D** | L3 每次强制确认 | `SKILL.md:17/19/21/23` 忽略规则 · 隐瞒用户 · 免确认执行 |
| js-skill | 34/100 | D | L3 每次强制确认 | `package.json` postinstall 下载执行 · `child_process.exec` |

单次评测 0.01–0.07 秒，纯本地，不出网。

<details>
<summary>真实输出（poisoned-skill，未删改）</summary>

```
🔒 第四维：安全检查（25分）
--------------------------------------------------
  ❌ combo.py:8: 凭证文件读取后网络外发（同文件污点）
  ❌ upload.py:8: 跨文件凭证外泄（引用 collect.py 读取的凭证后外发）

======================================================================
  ⛔ 安全否决：原始分 74 → 封顶 49（critical：命中文凭外泄 / 远程代码执行类问题）
  LGD Trust Score: 49/100  ⚠️ D
  🚦 建议执行权限: L3 沙箱运行（每次调用强制确认）
  评测耗时: 0.06s
======================================================================

  📋 扣分明细（得分 / 满分）:
    结构   ████████░░ 20/25
    目录   ████████░░ 12/15
    文档   ██████████ 20/20
    安全   ███░░░░░░░ 7/25
    生态   ██████████ 15/15
```

</details>

**这就是安全否决要解决的问题。** 同一份样本，加权平均给出 74 分 B 级——它清楚地读凭证、清楚地发往 `attacker.test`，却因为结构、文档、生态三维几乎满分被抬了上去。这是所有"加权总分"型扫描器的共同形态。

所以我们加了**安全一票否决**：命中「凭证外泄 / 远程代码执行」直接封顶 49 分、落到 L3（每次调用强制确认）；命中「凭证暴露 / 命令执行」封顶 69 分。上面那张表和折叠输出，就是修完之后重跑的同一个样本。

五维明细照常输出，原始分也照常显示——**封顶不隐藏信息，只纠正结论。**

这条规则不是我们发明的：

| 项目 | 做法 |
|---|---|
| guard0 | ≥1 个可利用 critical → 最高 D（≤69） |
| canopii | critical 封顶 20 · high 49 · medium 74 |
| DataWizual | 出现 CRITICAL 时有效等级封顶 C，数学分照报 |
| SonarQube | 门禁用条件判定，不看总分 |

共同逻辑一句话：**加权平均可以用来排序，不能用来下结论。**

### 用真实披露的攻击验证，而不是只测自己造的样本

2026-10-30，Mitiga 披露了针对 AI 指令文件的实战攻击（[原文](https://www.mitiga.io/blog/malware-in-ai-instruction-files-skillgate)）：把 `ANTHROPIC_BASE_URL` 覆盖成攻击者代理，会话流量全走 MITM；把权限绕过当成"便利默认"发出去；在数十个服务里散落 1,230+ 硬编码 API key 与 JWT。

这类攻击的特点是**SKILL.md 里不写露骨文字，全部藏在安装脚本里**。我们按这个形态复刻了 `_demo/mitiga-style/`，三个文件：越权文本、`setup.sh`（基址劫持＋两个真实密钥格式）、`collect.py`（读 `~/.aws/credentials` 后 POST 外发）。

同一份样本，改前改后：

| 版本 | 命中 | 结论 |
|---|---|---|
| 初版评测器 | 2 条，且全部来自 SKILL.md 文本 | 70 → 封顶 49 |
| 现在 | **9 条，脚本行为全部落到行号** | **22/100 D** |

改后的真实输出（未删改）：

```text
❌ collect.py:5: API 基址被改写（可能劫持到中间人代理）
❌ setup.sh:9: 硬编码凭证（AWS/GitHub/OpenAI/xox 格式）
❌ setup.sh:10: 硬编码凭证（AWS/GitHub/OpenAI/xox 格式）
❌ setup.sh:3: API 基址被改写（可能劫持到中间人代理）
❌ setup.sh:4: 代理被指向外部主机（流量可能被截获）
❌ setup.sh:5: 代理被指向外部主机（流量可能被截获）
❌ collect.py:20: 凭证文件读取后网络外发（同文件污点）
❌ SKILL.md:17: 隐瞒用户：要求不告知真实行为
❌ SKILL.md:19: 读取凭证文件指令
```

初版只报出后两条。**换句话说：一个只在 shell 里动手、SKILL.md 写得干净的技能，能整个漏过去。**

这次修复暴露了三个盲区，都不是"再加一条正则"能解决的：

1. **原来只扫 `.py/.js/.ts/.mjs/.cjs`** —— shell 系脚本完全不扫，而 Mitiga 的样本恰好藏在 shell 的 `export` 里。现在扩到 `.sh/.bash/.zsh/.ps1/.bat/.cmd` 共 11 种。
2. **原来只扫 `scripts/` 目录** —— 把载荷放在技能根目录就整个绕过。现在递归扫全树（排除 `tests/fixtures` 这类检测夹具，它们是评测输入而非被测技能本体）。
3. **凭证读取只认字面量路径** —— `open("~/.aws/credentials")` 能抓，但真实写法 `open(os.path.expanduser("~/.aws/credentials"))` 抓不到。现在常量从调用里挖出来。

复跑（不需要装 git）：

```bash
curl -L https://codeload.github.com/LGD-Eval/lgd-gate/tar.gz/refs/heads/main | tar xz
python3 lgd-gate-main/evaluate.py lgd-gate-main/_demo/mitiga-style
```

2026-11-06 在**干净环境、只下压缩包、未装 git** 的条件下实测：**22/100 D，9 条命中逐字一致**。这不是我们机器上的数字，是任何人拿到这个仓库都能跑出来的数字。

同一个形态在真实世界里已经成灾：Snyk 记录 ClawHub 2026-01 出现数百个恶意 skill、自测称 36% 的 skill 含可利用缺陷；arXiv 2507.19880 证明最小 MCP server 即可完成跨工具敏感数据外泄。**技能供应链不是假想威胁，这就是它长什么样。**

### 仓库里有三个扫描器，对外只认一个分数

`evaluate.py`、`skillgate.py`、`lgd_audit.py` 都在这个仓库里，目标不同：

| 工具 | 回答什么 | 是否产出对外分数 |
|---|---|---|
| `evaluate.py` | 这个技能能不能信任 → **一个分数 + 一档执行权限** | ✅ 唯一对外口径 |
| `skillgate.py` | 代码级危险模式（开发者自查） | ❌ 不评总分 |
| `lgd_audit.py` | 18 维完整性审计（开发者自查） | ❌ 不评总分 |

**为什么它们对同一份代码可能给出不同数字？** 因为扫描器扫自己时会出现自证误报——`skillgate.py` 曾把 `evaluate.py` 里的检测正则 `secret_re` 判成"硬编码凭证"、把规则词表里的 `~/.aws/credentials` 判成"读取凭证"，一度给自己打 0 分并"阻断发布"，而 `evaluate.py` 给同一目录 100 分。这不是能力问题，是**规则表被当成了行为**。

我们按 Bandit `# nosec` / SonarQube `NOSONAR` 的既有约定处理：`# skillgate: ignore` 必须与命中行同行，只对已确认的陪跑代码生效（如沙箱里造诱捕蜜罐的那行）。修完 `skillgate.py` 自扫从 **0/100 F（阻断）→ 95/100 A+（无阻断）**，同时四个恶意样本的分数一条没变——误报消掉了，检测力没掉。




<h1 align="center">🏛️ LGD-Eval</h1>

<p align="center">
  <strong>Independent Third-Party Agent Skill Evaluation</strong>
</p>

<p align="center">
  <a href="https://github.com/LGD-Eval/lgd-gate/actions"><img src="https://github.com/LGD-Eval/lgd-gate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python 3.8+"></a>
  <img src="https://img.shields.io/badge/offline-first-✅-success" alt="Offline first">
  <img src="https://img.shields.io/badge/zero--config-⚡-success" alt="Zero config">
</p>

---

> **We do not claim authority: we prove it with evidence.**
>
> 我们不宣称权威，我们用证据、流程与真实战绩证明它——以及敢于公布自己问题的自信。

---

## 🏛️ 官方身份 Official Identity

| 项 | 内容 |
|---|------|
| **理论** | LGD = Lifecycle Governance Doctrine（LGD 全程治理论） |
| **核心三律** | registered · evidenced · gated（有籍 · 有证 · 有门禁） |
| **理论 DOI** | 10.5281/zenodo.22456647（LGD 理论 Version 1.7） |
| **ORCID** | 0009-0001-0512-1237 |

---

## 📏 标准体系 Standards

### 五维评分（lgd-gate）

| 维度 | 满分 | 说明 |
|------|------|------|
| 结构完整性 | 25 | 文件齐不齐 |
| 目录结构 | 15 | 目录规不规范 |
| 文档质量 | 20 | 文档全不全 |
| 安全检查 | 25 | 有没有安全问题 |
| 生态兼容 | 15 | 能不能和 LGD 生态互链 |

### 等级

- A+: 90+
- A: 80-89
- B: 70-79
- C: 60-69

> 📖 完整的 L0-L13 企业级标准 → [evaluation-protocol.md](./docs/evaluation-protocol.md)
> 📖 Trust Score 双引擎口径声明：skillgate 扫描器（v3.1.2）与 evaluate.py 五维评测为两套评分口径，引用须标注引擎 + rule_version + 扫描对象 + 日期，详见 [SCORE-COMPARISON.md](https://github.com/LGD-Eval/evaluation-evidence/blob/main/evidence/71repo-scan-v3.1.0/SCORE-COMPARISON.md)。

### 风险分类（EU AI Act）

| 等级 | 说明 | 例子 |
|------|------|------|
| 不可接受风险 | 禁止 | 社会评分 |
| 高风险 | 严格监管 | 医疗、金融 |
| 中风险 | 透明义务 | 客服机器人 |
| 低风险 | 基本无义务 | 游戏 AI |

---

## 🔬 方法论 Methodology

| 原则 | 说明 |
|------|------|
| **Test-to-break** | 为找错而测试 |
| **全量实跑非抽样** | 100% 执行，没有抽检 |
| **独立复核（不自查）** | 自己不评自己，三权分立 |
| **证据优先可溯源** | 每个结论都有证据 |

---

## 🌳 Ecosystem / 生态系统

LGD-Gate is part of a larger ecosystem of Agent Skill tools. We are the **independent third-party evaluator** — the neutral referee.

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Skill 发布前流程                    │
└─────────────────────────────────────────────────────────────┘

  1. 开发技能 → 2. 写代码
       ↓
  3. [Snyk agent-scan] — 商业安全扫描（找漏洞）
       ↓
  4. [Trail of Bits] — 专业安全审计（深度审查）
       ↓
  5. [LGD-Gate] ← 我们在这里！独立第三方评测（18 维度）
       ↓
  6. [Tencent aig-agent-redteam] — 红队攻击模拟
       ↓
  7. [OpenAI security-best-practices] — 最佳实践检查
       ↓
  8. 发布！
```

### Complementary Tools / 互补工具

| Tool | What they do | What we do | How they fit together |
|------|-------------|-----------|----------------------|
| **[Snyk agent-scan](https://github.com/snyk/agent-scan)** | Commercial security scanning, find vulnerabilities | We do 18-dimension evaluation, not just security | They find bugs; we give an overall score |
| **[Trail of Bits](https://github.com/trailofbits)** | Deep security audit, professional penetration testing | We do independent, neutral rating | They audit; we verify and rate |
| **[Tencent aig-agent-redteam](https://github.com/Tencent/AI-Infra-Guard/tree/main/skills/aig-agent-redteam)** | Red team attack simulation | We also have red team dimension, but we are independent | They attack; we evaluate the attack surface |
| **[OpenAI security-best-practices](https://officialskills.sh/openai/skills/security-best-practices)** | Best practice checklist | We independently verify compliance | They write the standard; we test against it |

### Why we are unique / 我们的独特位置

- ✅ **Independent.** Three-way separation: theory / product / evaluation. We do not make what we evaluate.
- ✅ **Neutral.** We are not a security company, not a cloud provider, not a vendor.
- ✅ **Comprehensive.** 18 dimensions, not just security.
- ✅ **Evidence-based.** We publish our scores and our failures.

---

## 🏆 真实战绩 Track Record

| 项目 | 得分 | 等级 | 报告 |
|------|------|------|------|
| **MedXpert 医疗工具链** | 80/100 | B+ | [查看](./docs/evaluation-reports/) |
| **SkillGate 项目** | 73/100 | B+ | [查看](./docs/evaluation-reports/) |
| **LGD-Eval 自己** | 68/100 | C+ | 正在自我改进中 |

> **敢于公布问题的机构才配称权威！**

---

## 🏅 认证体系 Certification

五枚徽章：

| 徽章 | 说明 |
|------|------|
| **Verified** | 已验证 |
| **Audited** | 已审计 |
| **Evaluated** | 已评测 |
| **Timestamped** | 已加时间戳 |
| **Evidence-gated** | 证据门禁通过 |

技术：SHA-256 + 时间戳 + 区块链锚定

---

## 🏛️ 治理结构 Governance

| 原则 | 说明 |
|------|------|
| **三权分立** | 理论号 / 产品号 / 评测号，互不干涉 |
| **中立隔离红线** | 评测号不做产品，产品号不评测 |
| **领域负责人制度** | 每个领域有专人负责 |
| **全球参与** | 欢迎全球贡献者 |

---

## 🛠️ 我们的工具

| 工具 | 说明 |
|------|------|
| **lgd-gate** | 五维质量评测 |
| **lgd-audit** | 全方位审查（18 个维度） |

---

## 🚀 Quick Start

```bash
# 评测一个技能
python evaluate.py ./my-skill/

# 全方位审查（18 个维度）
python lgd_audit.py ./my-skill/

# 内部技能模式
python lgd_audit.py ./my-skill/ --internal
```

更多用法 → [docs/usage.md](./docs/usage.md)

---

## 🤝 贡献者制度

想参与？看 [CONTRIBUTORS.md](./CONTRIBUTORS.md)

---

## 📚 文档

| 文档 | 说明 |
|------|------|
| [评测协议 L0-L13](./docs/evaluation-protocol.md) | 完整评测标准 |
| [证据存证规范](./docs/evaluation-evidence.md) | 怎么存证、怎么验证 |
| [评测报告](./docs/evaluation-reports/) | 真实评测结果 |

---

## 📄 License

MIT License

---

*版本：v1.0.0 · 2026-10-28*

---

> 外部工具口径说明：OpenSSF Scorecard 是独立第三方指标，**不参与 LGD Trust Score 计算**，仅作参考陈列。本项目对外报分只有 LGD Trust Score 一个口径。
