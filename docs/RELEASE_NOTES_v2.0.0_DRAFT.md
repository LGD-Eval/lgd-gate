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

**EN** — In this order, none of which I will execute without a separate go-ahead:

1. Edit the **already-published `v1.1.0` release body** to retract the `L0 free-run` claim and point to `MIGRATION.md`. This is a write on shared state.
2. Tag **`v2.0.0`** (immutable) and move the rolling **`v2`** alias to it; keep `v1` / `v1.1.0` frozen, never force-pushed.
3. Publish these notes as the `v2.0.0` release body.
4. Only after the tag exists, switch README pins from `@v1` to `@v2` (3 places: `lgd-gate/README.md`, `LGD-Eval/README.md`, `LGD-Eval` docs) — pointing at `@v2` before the tag exists would 404.
5. Announce the `tier` semantics change wherever the Action is listed.

**中文** — 五步，顺序不能乱：先改已发布的 `v1.1.0` 说明撤回"L0 自由运行"那句（这是对共享状态的写入）；再打不可变 `v2.0.0` 并把滚动 `v2` 别名移过去，`v1`/`v1.1.0` 冻结、绝不强推；然后把这版说明作为 `v2.0.0` 发布正文；标签存在后，才把 README 里的 `@v1` 改成 `@v2`（三处，提前改会 404）；最后在 Action 出现的所有位置公告 `tier` 语义变更。
