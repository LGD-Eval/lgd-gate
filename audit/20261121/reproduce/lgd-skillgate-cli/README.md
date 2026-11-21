# lgd-skillgate

面向 AI Agent Skill 的**离线**静态扫描器：读 `SKILL.md` 与随附脚本，输出 Trust Score、grade、findings（含稳定规则 ID 与 `文件:行号`）。纯标准库、无网络、无遥测。

## 安装（本地，不联网 PyPI）

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install .
```

## 三条命令（陌生人可照抄）

```bash
# 1) 扫描一个恶意示例，期望 grade D、trust_score 40、命中 MD001 + CR010、exit 1
lgd-skillgate scan examples/malicious --format json

# 2) 扫描一个良性示例，期望 grade A、findings 0、exit 0
lgd-skillgate scan examples/benign --format json

# 3) 终端可读报告
lgd-skillgate scan examples/malicious
```

CI 用法：`lgd-skillgate scan ./skills --fail-under 70`，低于阈值即 exit 1。

## 能核什么（不要信文字，信输出）

- **规则可对位**：每条 finding 带规则 ID（如 `MD005`、`SH004`），可在源码里按 `文件:行号` 直接定位。
- **构建可识别**：`rule_version` 随规则增长递增；`--format json` 里含本次判定所用版本。
- **判定可复跑**：同一目录重复扫描结果稳定；无随机、无网络。
- **红队数字可自算**：仓库另附独立复算脚本，只读逐样本 `flagged` 字段重算 TP/FP/TN/FN，不调用扫描器。

## 明确不能做

- 不做动态沙箱执行，不执行被扫描代码。
- 不检测模型层提示注入的语义变体（只做模式与 AST/JS 静态规则）。
- 不提供"已获第三方认证"或"行业最强"类结论；本包只有 0 外部运行、0 外部评审。

## 许可

见 `LICENSE`（随仓文件原样保留，未改动署名）。
