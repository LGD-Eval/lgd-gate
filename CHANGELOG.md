# Changelog

## v3.2.1 (2026-11-28)

- fix(rules): `AU004` 正则 `\bCORS.*\*\b` 尾部的 `\b` 永远不成立（`*` 为非单词字符，其后不可能再有单词边界），
  该规则此前从未命中过；改为 `\bCORS[^\n]*\*`
- feat(profile): 新增 `scan --profile {default,strict}`；`strict` 把历史上未被任何循环消费的
  LC/QL/AU/VL 四张表接入扫描（21 条），默认 profile 行为与结果完全不变（161 条默认可执行）
- chore(rules): `EF001-EF004` 判定为 NT005/NT007/NT008/NT009 的重复登记，退役不再计入规则总数
  （186 → 182：默认 161 + strict-only 21）
- docs: 默认口径下信任分与 findings 未改动，历史期望值（恶意 D/40、良性 A/82）保持不变

## v1.0.0 (2026-10-28)

- Initial release
- Independent trust evaluation for AI agent skills
- Leaderboard and evaluation methodology
