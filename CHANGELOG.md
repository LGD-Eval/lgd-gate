# Changelog

## Unreleased — BREAKING (next major)

### Changed (breaking)

- **`tier` output: `L0`–`L5` permission ladder → `T0`–`T5` advisory risk tier.**
  The old ladder printed `L0 免审批（可直接运行，无需限流）` at ≥96, i.e. a score
  issued an execution grant. New tiers are labels only. Numeric boundaries
  unchanged; mapping table and consumer instructions in `MIGRATION.md`.
- `tier` is now a deprecated alias of the new `risk_tier` output and emits a
  `::warning::` annotation on every run.

### Added

- `authorization_status` output: always `NOT_GRANTED`.
- `grade` ladder gains `F` (<40), aligned with `skillgate.py`.
- `evaluate.py` is now a byte-identical copy of the canonical evaluator
  (`LGD-Eval/skills/lgd-eval/scripts/evaluate.py`), pinned by
  `tests/test_evaluator_provenance.py`. It previously diverged and lacked the
  JS combination rules (`73/100 B` where canonical says `49/100 D`).
- Sandbox child processes receive an allowlisted environment
  (`_sbox_env()`) instead of the full host environment.

### Fixed

- JS/TS credential and env exfiltration: whole-env bulk reads, credential
  paths, network sinks, and cross-file combinations (CRITICAL).

## v1.0.0 (2026-10-28)

- Initial release
- Independent trust evaluation for AI agent skills
- Leaderboard and evaluation methodology
