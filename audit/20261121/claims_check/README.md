# claims_check · 一条命令重算本仓公布的每个数字

文档写「D / trust 40」「12/12」「差分 0」「182 条」，代码一改就可能不成立，而人不会每次都核对。
这里把每条对外数字写成一条可执行断言：跑一遍，与文档不一致就 `exit 1`。

```bash
git clone --depth 1 https://github.com/LGD-Eval/lgd-gate.git && cd lgd-gate
python audit/20261121/claims_check/claims_check_20261128.py
```

纯标准库、离线、不需要任何凭据；不改仓内文件，只在同目录写 `claims_receipt_<date>.json`（`--no-receipt` 可关）。
回执带 `commit` 与 `skillgate.py` 的 sha256，锚定的是「这一份字节」，不是「大约某个版本」。

| ID | 断言 | 依据 |
|---|---|---|
| C01 | 恶意样本 → `D` / `40` / `MD001+MD007` / exit 1 | REPRODUCE §0.5 |
| C02 | 良性样本 → `A` / `82` / 0 findings / exit 0 | REPRODUCE §0.5 |
| C03 | `rule_version` = `v3.2.0` | skillgate.py |
| C04 | strict 档下恶意样本仍判 `D`，不崩不降级 | skillgate.py |
| C05 | L4 契约 12/12（默认引擎＝随仓引擎） | REPRODUCE §4 |
| C06 | 产品 12/12、参考 12/12、差分 0 | REPRODUCE §4 |
| C07 | 文档无过期口径（174 旧算法 / 持平 4 / 让读者 clone 不存在的分支） | REPRODUCE |
| C08 | 文档声明的现行条数 182 仍在文中 | REPRODUCE §4b |
| C09 | 代码指纹可锚定 | skillgate.py |

## 已验证能判红（不是橡皮章）

2026-11-28 在两份克隆上注入漂移，工具均 `exit 1` 并指名不符：

- `skillgate.py` 的 `rule_version` 改 `v3.2.9` → **C03 FAIL**（运行期漂移）
- 文档 `**182**` 改回 `**174**` → **C08 FAIL**（文档漂移）

## 它不证明什么

- 不证明工具更安全、规则更全；只证明「文档写的数字此刻在这份代码上仍然成立」。
- 不覆盖另一仓的 30 条一致性向量（`uibc-core` 的 `repro_kit`，见 REPRODUCE §1）。
- 不覆盖红队 114 样本的 TP/FP 口径（需外部语料目录，见 `redteam_recount`）。
- 仍是**自跑**；外部独立运行 0 不会因为本工具存在而改变。
