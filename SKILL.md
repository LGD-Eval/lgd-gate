---
name: lgd-gate
description: 独立第三方技能评测服务。对 AI Agent 技能进行独立的安全、质量、信任度评测，给出 Trust Score 和改进建议。当用户要做技能评测、独立检查、信任评分时使用。
version: 1.0.0
license: MIT
author: LGD-Eval
tags:
- 评测
- 安全
- 信任
- 独立第三方
---

# LGD-Gate: Independent Skill Evaluation

## When to Use

- 你想独立评测一个 AI Agent 技能的安全性和质量
- 你想给一个技能打 Trust Score
- 你想找改进建议
- 你想做第三方安全审计

## Usage

```bash
python evaluate.py path/to/skill/
```

输出：
- Trust Score (A+ to D)
- 安全发现
- 质量发现
- 改进建议

## What It Checks

1. **安全检查**：有没有硬编码密钥、危险代码、网络泄漏
2. **质量检查**：SKILL.md 是否完整、描述是否清晰、示例是否可运行
3. **信任评分**：综合打分，A+ 到 D 五个等级

## Known Limits

- 静态分析，不运行技能
- 主要检查常见模式，不保证 100% 覆盖
- 独立第三方评测，仅供参考
