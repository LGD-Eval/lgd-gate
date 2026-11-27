<h1 align="center">🏛️ LGD-Eval</h1>

<p align="center">
  <strong>独立第三方 Agent Skill 评测机构</strong>
</p>

<p align="center">
  <a href="https://github.com/LGD-Eval/lgd-gate/actions"><img src="https://github.com/LGD-Eval/lgd-gate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python 3.8+"></a>
</p>

---

> **我们不宣称权威，我们用证据、流程与真实战绩证明它——以及敢于公布自己问题的自信。**

---

## 🏛️ 官方身份

| 项 | 内容 |
|---|------|
| **理论** | LGD = Lifecycle Governance Doctrine（LGD 全程治理论） |
| **核心三律** | registered · evidenced · gated（有籍 · 有证 · 有门禁） |
| **DOI** | 10.5281/zenodo.22456647 (v1.7.0) |
| **ORCID** | 0009-0001-0512-1237 |

---

## 📏 标准体系

| 等级 | 名称 | 说明 |
|------|------|------|
| L0-L13 | 测试专家手册 | 14 级评测标准 |
| D1-D10 × R1-R3 | 证据门禁查重协议 | 防作弊、防重复 |

---

## 🔬 方法论

| 原则 | 说明 |
|------|------|
| **Test-to-break** | 为找错而测试 |
| **全量实跑非抽样** | 100% 执行，没有抽检 |
| **独立复核（不自查）** | 自己不评自己，三权分立 |
| **证据优先可溯源** | 每个结论都有证据 |

---

## 🏆 真实战绩

| 项目 | 结果 |
|------|------|
| **MedXpert 医疗工具链** | 21 模块全量实跑，20 通过，发现 1 个自检硬伤 |
| **SkillGate 项目** | 独立验收发布阻断 P1/P2 修复清单已公布 |

> **敢于公布问题的机构才配称权威！**

---

## 🏅 认证体系

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

## 🏛️ 治理结构

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

## 🚀 快速开始

```bash
# 评测一个技能
python evaluate.py ./my-skill/

# 全方位审查（18 个维度）
python lgd_audit.py ./my-skill/

# 内部技能模式
python lgd_audit.py ./my-skill/ --internal
```

更多用法 → [docs/usage-zh.md](./docs/usage-zh.md)

---

## 🤝 贡献者制度

想参与？看 [CONTRIBUTORS.md](./CONTRIBUTORS.md)

---

## 📄 许可证

MIT License

---

*版本：v1.0.0 · 2026-10-28*
