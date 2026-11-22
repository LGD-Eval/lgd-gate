# lgd-skillgate

面向 AI Agent Skill 的**离线**静态扫描器：读 `SKILL.md` 与随附脚本，输出 Trust Score、grade、findings（含稳定规则 ID 与 `文件:行号`）。纯标准库、无网络、无遥测。

## 安装

```bash
pip install lgd-skillgate        # PyPI 0.1.0
```

或从源码：

```bash
git clone -b docs/reproduce-20261121 --depth 1 https://github.com/LGD-Eval/lgd-gate.git
cd lgd-gate/audit/20261121/reproduce/lgd-skillgate-cli
python -m venv .venv && pip install .     # Windows: .venv\Scripts\activate
```

## 三条命令（陌生人可照抄）

```bash
# 1) 恶意示例：期望 grade D / trust 40 / 命中 MD001 + CR010 / exit 1
lgd-skillgate scan examples/malicious --format json

# 2) 良性示例：期望 grade A / trust 82 / findings 0 / exit 0
lgd-skillgate scan examples/benign --format json

# 3) 终端可读报告
lgd-skillgate scan examples/malicious
```

CI 用法：`lgd-skillgate scan ./skills --fail-under 70`，低于阈值即 exit 1。

## 能核什么（不要信文字，信输出）

- **规则可对位**：每条 finding 带规则 ID（如 `MD005`、`SH004`），可在源码里按 `文件:行号` 直接定位。
- **构建可识别**：json 输出含 `rule_version`（当前 `v3.2.0`）。
- **判定可复跑**：同一目录重复扫描结果稳定；无随机、无网络。
- **红队数字可自算**：仓库另附独立复算脚本，只读逐样本 `flagged` 字段重算 TP/FP/TN/FN，不调用扫描器。

## 明确不能做

- 不做动态沙箱执行，不执行被扫描代码。
- 不检测模型层提示注入的语义变体（只做模式与 AST/JS 静态规则）。
- 不提供"已获第三方认证"或"行业最强"类结论；截至 2026-11-21，外部独立运行 **0**、外部评审 **0**，竞品矩阵 18 维为 **0 领先 / 4 持平 / 14 落后**。

## 版本

0.1.0（2026-11-21，PyPI 首发）— 规则 `v3.2.0`，共 174 条（155 + 19）。

## 许可

见 `LICENSE`（随仓文件原样保留，未改动署名）。
