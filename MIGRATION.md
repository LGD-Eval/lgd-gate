# Migration: `tier` output, L0–L5 → T0–T5 / 迁移说明：`tier` 输出，L0–L5 → T0–T5

**Applies to:** LGD Skill Gate action, versions after the authorization split / 适用于授权分离之后的版本

---

## What changed and why / 改了什么，为什么

**EN** — The `tier` output used to be a **permission ladder**: `L0` meant `免审批（可直接运行，无需限流）`, and a score of 96+ would hand that to any workflow that read the output. A number was signing an execution grant. That is exactly what the audit's first P0 is about, so the ladder is gone.

`tier` now emits an **advisory risk tier** `T0`–`T5`. The numeric boundaries are unchanged, so a mapping is mechanical — but the meaning is not: **`T0` is "low risk", never "approved"**. Authorization is a separate act by a named human or an unrelated third party, and `authorization_status` is `NOT_GRANTED` on every run.

**中文** — 旧的 `tier` 是一条**权限阶梯**：`L0` 的含义是"免审批、可直接运行"，96 分以上就把它交给任何读这个输出的工作流。一个数字在签发执行许可，这正是审计里的第一个 P0。所以阶梯没了。

现在 `tier` 输出的是**风险档位** `T0`–`T5`。数值分界没变，所以映射是机械的；但含义变了：**`T0` 是"风险低"，永远不是"已批准"**。授权是另一次动作，由具体的人或无关第三方单独完成，而 `authorization_status` 每次都是 `NOT_GRANTED`。

---

## Mapping table / 映射表

| Score / 分数 | Old output / 旧输出（已移除） | Old meaning / 旧含义 | New output / 新输出 | New meaning / 新含义 |
|---|---|---|---|---|
| ≥ 96 | `L0` | 免审批，可直接运行，无需限流 | `T0` | 风险极低（仅供参考） |
| 81–95 | `L1` | 一次性确认（限流 60 次/分） | `T1` | 风险低（仅供参考） |
| 51–80 | `L2` | 人工复核（限流 30 次/分） | `T2` | 风险中等（仅供参考） |
| 31–50 | `L3` | 沙箱运行（每次调用强制确认） | `T3` | 风险较高（建议先过沙箱） |
| 11–30 | `L4` | 隔离环境（仅允许只读调用） | `T4` | 风险高（建议隔离只读） |
| 0–10 | `L5` | 拒绝执行（需重写后重新评测） | `T5` | 风险极高 |

**EN** — The right-hand column is a *label*, not a *decision*. If your workflow needs "may this run in production?", the answer is not in this table — it must come from an authorization record.

**中文** — 右列是**标签**，不是**决定**。如果你的工作流要问"这段代码能不能上生产"，答案不在这张表里——它只能来自一份授权记录。

---

## What to change in your workflow / 工作流需要改什么

**EN**

1. **Do not remap `T0` back to "allow".** If your job gated a deploy on `tier == 'L0'`, that gate was issuing permission from a score. Replace it with an explicit approval step, and keep `tier` only as a review signal.
2. **Rename the reference.** `risk_tier` is now also emitted (same value as `tier`) so new code can use a name that says what it is. `tier` stays as a deprecated alias for one major version.
3. **Read `authorization_status`.** It is `NOT_GRANTED` unconditionally; treat anything else as a broken contract, not as a grant.
4. **Pass a threshold.** The CLI exits `0` by default — a bare `python3 evaluate.py ./skill` is an *evaluation*, not a *gate*. Only `--fail-under N` turns it into a gate (the action passes `--fail-under` from the `threshold` input, default 90).

**中文** — 四条：别把 `T0` 映射回"放行"（如果你的门禁曾判 `tier == 'L0'` 才允许部署，那个门禁是在拿分数签发许可，应换成显式审批步骤）；改用 `risk_tier` 这个名字；读 `authorization_status`，出现非 `NOT_GRANTED` 要当成契约坏了；一定带阈值，裸跑 CLI 默认退 0，那不是门禁。

---

## Deprecation schedule / 废弃时间表

**EN** — `tier` emits a `::warning::` annotation on every run so consumers that forgot about this change see it in the job log (the same idea as GitHub's brownouts: make the change visible before it is unavoidable). Removal of the alias is a later major version; this migration does not remove it.

Measured against the v2.0.0 publication date (W), not against today — a schedule anchored to an unpublished release would be fiction:

| Milestone | When | What changes |
|---|---|---|
| `W` | v2.0.0 published | `tier` starts emitting `T0`–`T5` + `::warning::` every run; `risk_tier` available |
| `W+90d` | 90 days after publication | warning drops to a single line in the step summary, then to release notes only |
| `W+180d` | 180 days after publication | `tier` removed; `risk_tier` is the only output. Ships in the next major, never in a patch |

**Known consumers (surveyed 2026-11-15):** no repository in this ecosystem reads `outputs.tier`. The only references are this repo's own `action.yml`, its tests, and prose in `MIGRATION.md` / `CHANGELOG.md`. The three `uses: LGD-Eval/lgd-gate@v1` examples are documentation pins, not live workflows. Outside this ecosystem, Marketplace consumers are unknown and cannot be enumerated — which is why the per-run warning, not the release note alone, carries the message.

**中文** — 每次运行都给一条 `::warning::` 注解，忘记改的消费者会在作业日志里看到（和 GitHub 的 brownout 一个思路：在不可回避之前先让它可见）。删掉这个别名留给下一个大版本，本次不删。

时间表以 `v2.0.0` 发布日（W）为锚点，不以今天为锚点——挂在一个还没发布的版本上的排期是假的：

| 里程碑 | 时点 | 变化 |
|---|---|---|
| `W` | `v2.0.0` 发布 | `tier` 开始输出 `T0`–`T5` 并每次打 `::warning::`；`risk_tier` 可用 |
| `W+90d` | 发布后 90 天 | 警告降为步骤摘要一行，再降为仅发布说明 |
| `W+180d` | 发布后 180 天 | 删除 `tier`，`risk_tier` 成为唯一输出；随下一个大版本发布，绝不出现在补丁版里 |

**已核实的消费者（2026-11-15 扫过）：** 本生态里没有任何仓库读 `outputs.tier`——只有本仓自己的 `action.yml`、测试、以及 `MIGRATION.md` / `CHANGELOG.md` 的说明文字。三处 `uses: LGD-Eval/lgd-gate@v1` 是文档示例，不是活的作业。生态之外的 Marketplace 消费者无法枚举——这正是为什么由每次运行的警告、而不只是发布说明，来传递这条消息。
