# Amendment to the v1.1.0 release description / 关于 v1.1.0 发布说明的更正

**Status:** DRAFT — not published. / **状态：草稿，未发布。**

**Applies to:** `LGD-Eval/lgd-gate` release `v1.1.0` (published 2026-11-06), tag `3bff151`, and the rolling `v1` alias pointing at it. / **适用于：`v1.1.0` 发布（2026-11-06 发布，标签 `3bff151`）及其滚动别名 `v1`。**

---

## The sentence being amended / 被更正的句子

**EN** — The `v1.1.0` release notes say:

> *"One 0-100 Trust Score, mapped to an execution tier (L0 free-run to L5 deny)"*

That described the shipped behaviour accurately. It is also wrong as a governance claim, and this amendment retracts the claim — not the software.

**中文** — `v1.1.0` 的发布说明里写着"分数映射到执行档位（L0 自由运行到 L5 拒绝）"。它如实描述了已发布代码的行为，但作为治理主张是错的。本更正撤回的是**这个主张**，不是这个软件。

---

## Why it is wrong / 为什么错

**EN** — An evaluation produces a measurement. An authorization is a decision that a named party makes, with a scope and a validity period, and that can be audited afterwards. Collapsing the first into the second means a number signs for a person: at ≥96 the evaluator printed `L0 免审批（可直接运行，无需限流）`, and any workflow reading that output inherited an execution grant nobody granted.

Two things follow, and both are uncomfortable:

1. **The number cannot know.** It measures static patterns in a directory. It does not know the deployment context, the data the skill will touch, or who is accountable if it misbehaves.
2. **The grant cannot be withdrawn.** A score has no expiry, no granter, and no scope — so there is nothing to revoke when conditions change.

**中文** — 评测产出的是测量结果；授权是**具名一方**做出的决定，有范围、有有效期、事后可审计。把前者折叠成后者，等于让一个数字替人签字：96 分以上就打印"免审批（可直接运行，无需限流）"，任何读到这个输出的工作流就继承了一份没人授予的执行许可。

由此有两点，都不好受：**数字不可能知道**（它只测目录里的静态模式，不知道部署上下文、不知道技能会碰什么数据、不知道出事后谁负责）；**许可无法撤回**（一个分数没有有效期、没有授予人、没有范围，条件变了也无从撤销）。

---

## What v1.1.0 actually provides / v1.1.0 实际提供什么

**EN** — Still the same software, described as what it is:

| Claim in the original notes | Corrected statement |
|---|---|
| "One 0-100 Trust Score" | A reproducible 0-100 measurement over static, sandboxed and (optionally) LLM-reviewed layers, with a per-file and whole-tree hash pin so the artifact is identifiable |
| "mapped to an execution tier (L0 free-run to L5 deny)" | **No longer claimed.** The score is an input to a human decision. `v1.1.0` also printed an L0–L5 *suggestion*; `v2.0.0` replaces it with a T0–T5 risk tier and reports `authorization_status: NOT_GRANTED` on every run |
| "SARIF 2.1.0 output" | unchanged |
| "Evidence chain with sha256 pins" | unchanged |

**中文** — 同一份软件，照实描述：分数是可复现的测量（静态 + 沙箱 + 可选 LLM 复核，带逐文件与整树哈希钉住）；"映射到执行档位"**不再主张**——分数是人做决定的输入，v1.1.0 还额外打印了一个 L0–L5 *建议*，v2.0.0 把它换成 T0–T5 风险档位并每次报 `authorization_status: NOT_GRANTED`；SARIF 与证据链不变。

---

## Recommended application / 建议的落地方式

**EN** — Two options; the second is what I recommend, because editing a published body leaves no visible trace of the edit:

| Option | What happens | Trace |
|---|---|---|
| A. Edit the `v1.1.0` release body in place | Replace the sentence, no marker | Edit history is invisible to readers |
| **B. Publish this amendment** (as `docs/AMENDMENT_v1.1.0.md` on `main`, plus a one-line note prepended to the `v1.1.0` body linking to it) | Original text stays; correction is dated and signed | Both versions visible, which is the point |

**中文** — 两个选项，推荐 B：发布正文一旦就地改写，读者看不出"这句被改过"。B 让原文留存、更正带日期与署名，两版都可见——这才是更正该有的样子。

**EN — Proposed one-line note to prepend to the `v1.1.0` body:**

> ⚠️ **Amended 2026-11-15:** this release described a score as issuing an execution tier. That claim is withdrawn — see `docs/AMENDMENT_v1.1.0.md`. v2.0.0 separates evaluation from authorization.

**中文 — 建议置于 v1.1.0 正文首行的一句话：**

> ⚠️ **2026-11-15 更正：** 本发布说明曾把分数描述为签发执行档位。该主张已撤回，见 `docs/AMENDMENT_v1.1.0.md`。v2.0.0 已将评测与授权分离。

---

## Scope of this amendment / 本次更正的范围

**EN** — It covers the release notes and the two repository descriptions that repeat the claim (`lgd-gate`: "One score, one permission tier"; `LGD-Eval`: "a score that ends in a permission decision"). It does **not** cover the `v1.1.0` software: that build behaves as the original text said, and `v1` stays frozen at `3bff151` — no force-push, no re-tag. Users on `@v1` keep the old behaviour until they move to `@v2`; telling them so is part of the amendment, not a footnote.

**中文** — 覆盖发布说明，以及重复这句话的两处仓库简介。**不覆盖** v1.1.0 的软件本身：那个版本的行为确实如原文所述，`v1` 冻结在 `3bff151`，不强推、不改标签。`@v1` 的用户在迁到 `@v2` 之前继续拿到旧行为——把这件事说清楚是更正的一部分，不是脚注。

---

## Nothing here is published / 这里没有任何东西被发布

**EN** — This file is a draft in a local branch. Publishing the amendment, editing the two descriptions, and adding the one-line note to the release body all require Steven Zhao's separate approval.

**中文** — 本文件是本地分支上的草稿。发布更正、改两处简介、在发布正文加一句话，都需要 Steven Zhao 单独批准。
