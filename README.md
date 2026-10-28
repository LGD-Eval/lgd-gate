<h1 align="center">🏛️ LGD-Eval</h1>

<p align="center">
  <strong>Independent Third-Party Agent Skill Evaluation</strong>
</p>

<p align="center">
  <a href="https://github.com/LGD-Eval/lgd-gate/actions"><img src="https://github.com/LGD-Eval/lgd-gate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python 3.8+"></a>
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
