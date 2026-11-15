# DRAFT — v2.0.0 release notes / v2.0.0 发布说明（草稿，未发布）

**Status:** DRAFT. Nothing here has been published. Publication needs Steven Zhao's approval. / **状态：草稿。本文件内容未发布，发布需 Steven Zhao 批准。**

---

## Headline / 一句话

**EN** — A score no longer grants permission. `v2.0.0` separates evaluation from authorization: every run reports `authorization_status: NOT_GRANTED`, and the `tier` output now carries an advisory risk tier `T0`–`T5` instead of an `L0`–`L5` permission ladder.

**中文** — 分数不再签发权限。`v2.0.0` 把评测与授权分开：每次运行都报 `authorization_status: NOT_GRANTED`，`tier` 输出改成一个**参考性风险档位** `T0`–`T5`，不再是 `L0`–`L5` 权限阶梯。

---

## Why this is a breaking change, stated plainly / 为什么这是破坏性变更，说清楚

**EN** — `v1.1.0`'s release notes said: *"One 0-100 Trust Score, mapped to an execution tier (L0 free-run to L5 deny)."* That sentence described real behaviour: at ≥96 the evaluator printed `L0 免审批（可直接运行，无需限流）`. A number was issuing an execution grant. Anyone who wired `tier == 'L0'` into a deploy job was deploying on the strength of a score.

`v2.0.0` removes that. It is breaking **on purpose** — the previous behaviour is the defect, not a feature to preserve.

**中文** — `v1.1.0` 的发布说明里写着"分数映射到执行档位（L0 自由运行到 L5 拒绝）"，而代码真的在 96 分以上打印"免审批（可直接运行，无需限流）"。一个数字在签发执行许可；任何把 `tier == 'L0'` 接进部署作业的人，都是在凭一个分数上线。

`v2.0.0` 把这个删掉。它是**故意**破坏性的——旧行为本身就是缺陷，不是要保留的特性。

---

## What changed / 变更内容

**EN**

1. **Authorization split.** `authorization_status` is `NOT_GRANTED` on every run and in `--evidence-json`. There is no path from a score to a grant.
2. **`tier` → risk tier.** `L0`–`L5` becomes `T0`–`T5`. Boundaries unchanged, meaning changed: `T0` is "low risk", not "approved". `risk_tier` is the new name; `tier` is a deprecated alias that emits a `::warning::` on every run.
3. **Provenance.** `--provenance self|automated|third_party` (default `self`). A maintainer self-review or a CI run can no longer be presented as third-party certification.
4. **Grade scale.** `F` (<40) added, aligning this evaluator with `skillgate.py` — the same 34 is no longer `D` here and `F` there.
5. **JS/TS exfiltration.** Whole-env bulk reads (`Object.entries(process.env)`, spreads, `Object.keys`, `Object.assign`), credential paths, network sinks, and **cross-file combinations** (file A reads credentials and is imported by file B which sends) — graded CRITICAL.
6. **Sandbox.** The child process gets an allowlisted environment (`_sbox_env`), not `dict(os.environ)`; a Node entry point (`lgd_node_probe.js`) is now supported alongside Python.
7. **One evaluator.** This Action now runs a byte-identical copy of the canonical evaluator, pinned by a test. Previously it shipped a divergent copy that graded the cross-file exfiltration probe **73/100 B** where canonical says **49/100 D**.
8. **Default threshold 90 → 60** (pending approval, A-17). At 90, half of a 10-sample clean corpus failed CI (75/75/75/78/80 — every one with a full security dimension and zero findings). They failed for being thin, not for being dangerous. 60 keeps 11 points of margin above the veto cap of 49, and on that corpus it produces 0% FPR and 0% FNR. **Anyone who relied on 90 as a template-compliance gate must pass `threshold: 90` explicitly** — the template gate still exists, it just stops being the default.
9. **`safety_veto` gained three fields** (consumer-visible contract change): `triggered` (a critical rule fired), `applied` (the cap actually lowered the score), `critical_rules` (which ids). **A gate that reads only `applied` can pass a skill that hit a critical rule** — a 46-score skill with `applied: false` is exactly that case. Gate on `triggered` plus the score.
10. **Dependency coverage.** Manifests and lockfiles (incl. `pyproject.toml`, `package.json`, `package-lock.json`, `poetry.lock`); at most 10 pinned dependencies queried per run, the remainder reported as unqueried; ranges never get an invented version; offline degrades to "could not check", which is **weaker than a pass**. Typosquatting is a name-similarity hint only, and only LOW.

**中文** — 八至十条：**默认门槛 90 → 60**（待批，A-17）——在 90 上，10 份干净样本被拦 5 份，分数 75/75/75/78/80、安全维度全满、零发现，它们是因为"写得薄"被拦；60 比封顶 49 留 11 分余量，该语料上 0% 误杀 0% 漏放，**原先依赖 90 作模板合规线的人需显式传 `threshold: 90`**。**`safety_veto` 增加三个字段**（消费者可见契约变更）：`triggered`（是否命中关键规则）/`applied`（封顶是否真的压低了分数）/`critical_rules`——**只读 `applied` 的门禁会放过命中关键规则的技能**，46 分且 `applied: false` 就是这种情形，门禁请判 `triggered` 与分数。**依赖覆盖面**：读清单与锁文件、每次最多 10 个固定版本、范围不猜版本、离线降级为"无法核查"（比通过更弱）；仿名只做名称相似度提示且只报 LOW。

**中文** — 七条：授权分离、`tier` 改风险档位、来源声明、等级补 F、JS 外泄（含跨文件组合）、沙箱白名单 + Node 入口、评估器统一为唯一副本（此前 Marketplace 那份把跨文件外泄判 73/B，正典是 49/D）。

---

## Migration / 迁移

**EN** — See `MIGRATION.md`: the L→T table, and four actions — don't remap `T0` to "allow", use `risk_tier`, read `authorization_status`, and pass `--fail-under` (a bare CLI run exits 0: it is an evaluation, not a gate).

**中文** — 见 `MIGRATION.md`：L→T 映射表，以及四条动作——别把 `T0` 映射回放行、改用 `risk_tier`、读 `authorization_status`、带 `--fail-under`（裸跑 CLI 退 0，那是评测不是门禁）。

---

## Known limits, not rounded off / 已知边界，不修饰

**EN**

| Limit | Consequence |
|---|---|
| `authorization_status` is a constant, not a state machine | there is no record format for "who granted what"; a grant lives outside this tool |
| `--provenance` is self-declared | nothing stops a maintainer typing `third_party` |
| The pin is a hash, not a signature | it proves "same as then", not "approved by whom" |
| Static analysis sees syntax, not behaviour | a skill that fetches its payload at runtime still needs the L3 sandbox, which needs docker or Linux |
| Grading is calibrated against our own samples | benign samples were measured 17–20 points apart between the two engines; not unified yet |

**中文** — 五条：授权状态是常量不是状态机；来源靠自填；钉住是哈希不是签名；静态看语法不看行为；良性样本两引擎差 17–20 分，尚未统一。

---

## Publication checklist (requires approval) / 发布清单（需批准）

**EN** — In this order, none of which I will execute without a separate go-ahead. Steps 0–1 come first because they address claims that are already public, and a new release does not retract them by itself:

0. **Merge the branch** (so the corrected READMEs on `main` stop saying `分数决定权限` / `免审批直接执行` — both main READMEs still carry it today).
1. **Publish `docs/AMENDMENT_v1.1.0.md`** and prepend its one-line note to the **already-published `v1.1.0` release body**; also rewrite the two repository descriptions that repeat the claim (`lgd-gate`: "One score, one permission tier"; `LGD-Eval`: "a score that ends in a permission decision"). All three are writes on shared state.
2. Tag **`v2.0.0`** (immutable) and move the rolling **`v2`** alias to it; keep `v1` / `v1.1.0` frozen, never force-pushed.
3. Publish these notes as the `v2.0.0` release body.
4. Only after the tag exists, switch README pins from `@v1` to `@v2` (3 places: `lgd-gate/README.md`, `LGD-Eval/README.md`, `LGD-Eval` docs) — pointing at `@v2` before the tag exists would 404.
5. Announce the `tier` semantics change wherever the Action is listed.

**中文** — 六步，顺序不能乱。第 0–1 步排在最前，因为它们处理的是**已经公开**的主张，发一个新版本本身并不能把它们收回：先合并分支（两个仓 main 上的 README 今天还在写"分数决定权限"/"免审批直接执行"）；再发布 `docs/AMENDMENT_v1.1.0.md` 并把那一行更正加到已发布的 `v1.1.0` 正文首行，同时改掉重复这句话的两处仓库简介（这三处都是对共享状态的写入）；然后打不可变 `v2.0.0` 并移 `v2` 别名，`v1`/`v1.1.0` 冻结、绝不强推；然后把这版说明作为 `v2.0.0` 正文；标签存在后才改 README 的 `@v1`→`@v2`（提前改会 404）；最后公告 `tier` 语义变更。
