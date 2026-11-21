# 意图判别层（v3）：规则取证 + 意图裁决

**日期**：2026-11-19
**性质**：候选模块（新增，不改 `lgd-gate` 主分支）
**定位**：承接上一轮结论——正则规则在未见攻击族上召回 0.333，必须换判别模型

---

## 1. 架构

```
技能目录
   ├── 规则层（skillgate 24 条 rule_id）→ 取证：哪一行、哪条规则
   └── 意图层（intent_engine）        → 裁决：能力组合是否是危险意图
                                        ↓
                              合并判定（任一非 ALLOW 即拦截）
```

**关键设计**：规则不再是判据，而是**证据清单**。意图层看的是"这个技能具备哪些能力、组合起来能做什么"。

判定契约（不可协商）：

```
verdict ∈ {ALLOW, REVIEW, DENY, UNKNOWN}
无文件 / 解析失败 → UNKNOWN（fail-closed，调用方必须按不可放行处理）
本结果只表示风险判定，绝不等于授权
```

---

## 2. 能力维度（8 类，机器可判）

`credential_access`、`network_egress`、`download`、`dynamic_exec`、
`binary_exec`、`persistence`、`destruction`、`privilege`、`obfuscation`、`security_disable`

## 3. 策略表（11 条组合规则）

| ID | 能力组合 | 判定 | 理由 |
|---|---|---|---|
| P01 | 凭据 + 外发 | DENY | 完整外泄链 |
| P02 | 下载 + 动态执行 | DENY | 远端代码执行 |
| P03 | 解码 + 动态执行 | DENY | 静态检查绕过 |
| P04 | 破坏系统路径 | DENY | 不可恢复 |
| P05 | 持久化 + 外连 | DENY | 后门常驻 |
| P06 | 持久化 | REVIEW | 需人工确认用途 |
| P07 | 提权/特权容器 | REVIEW | 需确认必要性 |
| P08 | 访问凭据 | REVIEW | 需确认是否必要 |
| P09 | 动态执行 + 网络 | DENY | 参数里的 RCE |
| P10 | 关闭防护 | DENY | 为载荷清场 |
| P11 | 下载 + 执行二进制 | DENY | 投放链 |

---

## 4. 单元测试 10/10（`test_intent.py`）

```
PASS  凭据+外发 → DENY
PASS  下载+执行 → DENY
PASS  解码+执行 → DENY
PASS  破坏系统目录 → DENY
PASS  关闭防护 → DENY
PASS  持久化 → REVIEW
PASS  仅访问凭据 → REVIEW
PASS  普通构建 → ALLOW
PASS  普通 HTTP GET → ALLOW
PASS  空目录 fail-closed → UNKNOWN
```

中途两个失败暴露真实缺口并已修：
- `curl -o … && /tmp/a` 未被判"执行"→ 新增 `binary_exec` 能力 + P11
- `… | base64 -d | sh` 未算"动态执行"→ `dynamic_exec` 加入"管道落到解释器"

**这两个修正来自单元测试（通用原则），不是来自测试集。**

---

## 5. 效果（干净集）

| 语料 | 规则层单跑 | **混合（规则+意图）** |
|---|---|---|
| **test7（12，构建后未再调参）** | recall 0.667 / FPR 0.000 | **recall 0.833 / precision 1.000 / FPR 0.000** |
| test5（前一轮的干净集，本轮未用于设计） | 0.333 | 0.833 / 0.833 / 0.167 |
| test6（已污染，仅供参考） | 0.667 | 1.000 / 0.857 / 0.167 |

**这是六轮里第一次在"没见过的语料"上拿到真实提升**：+0.166 recall，误报未增加。

但也必须说清：
- 提升幅度是 0.667→0.833，**不是 1.00**。剩下一条 X02 `nc -lvp 4444 -e /bin/bash` 漏报——
  SH010 的正则要求 `nc` 紧跟带 `e` 的参数，`nc -lvp 4444 -e` 中间隔了参数，匹配不上。
- 修法已定位（`\bnc\b[^\n]*\s-[a-z]*e\b`），但**刻意没改**：test7 已用于诊断，再改就成了又一轮自证。
  下一次改动必须落在新的第 8 套语料上。

---

## 6. 为什么这条路能走通（而不是继续加规则）

| 漏报族 | 规则层为什么无解 | 意图层怎么解 |
|---|---|---|
| 供应链（clone+make install） | 每个命令都合法 | 能力组合"下载 + 执行" |
| 后门（写 authorized_keys） | 写文件本身合法 | `persistence` 能力 |
| 参数里的 RCE | 语义在字符串参数里 | `dynamic_exec` 扫参数文本 |
| 删盘 | 不在任何字符串类别 | `destruction` 路径分级 |

**规则问"这句话是不是危险字符串"，意图问"这套能力能干什么"。**

---

## 7. 下一步（按性价比）

1. **接入真实模型**：`intent_engine` 现在输出 evidence pack（能力清单 + 证据行），
   把这份 pack 交给模型做"意图复核"，模型只回答"这些能力组合是否构成风险"，
   不给它看整篇文本——降低 token 成本、也降低被提示注入影响的空间。
2. **沙箱引爆**：静态看不到的（V06 dd 写盘）只能靠真跑。
3. **119 个真实 SKILL.md 回归**：误报清零是产品能否对外说"可用"的门槛。
4. 第 8 套语料 + 一次盲测（找非作者写样本）。

---

## 8. 边界

- 语料仍由作者编写，存在系统性盲区（NOT VERIFIED 真实分布）。
- 意图层是**确定性策略表**，不是模型；对"合法但意图恶意"的组合仍有盲区（如合法备份工具批量读密钥）。
- REVIEW 档会产生人工成本，测试中 W10（读 `.env` 打印长度）就被判 REVIEW——这是**设计取舍**，不是 bug。
- 未与竞品同语料横评（BLOCKED）。
- 本模块未进入 `lgd-gate` 主分支，也未接入 CI（需批准）。

---

## 9. 运行

```powershell
python intent_engine.py <skill_dir> --format json      # exit 0=ALLOW，非 0=需处理
python test_intent.py                                   # 10/10

# 混合基准
$env:COMBINE='1'; $env:INTENT_ENGINE='<abs>\intent_engine.py'
$env:BENCH_SPLIT='test7'; python run_redteam_bench.py
```
