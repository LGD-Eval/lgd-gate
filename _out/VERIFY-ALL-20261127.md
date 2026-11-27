# 一键复跑总闸 — 20261127

**VERDICT: PASS**｜7 PASS / 1 SKIP / 8 项｜总耗时 3.9 s｜引擎目录 `D:\lgd-work\roadmap-run\dist\repo_probe\lgd-gate-main`

## 引擎指纹

| 文件 | sha256[:16] | 字节 |
|---|---|---|
| scanner.py | `cfd7dcdc628d183c` | 67761 |
| gate.py | `05ad317eb65744d8` | 16865 |
| adjudicator.py | `cbb41e59d35db917` | 11001 |
| claims.py | `609eb7cdb7cf57bb` | 4589 |

## 夹具指纹（防“改了夹具再宣称通过”）

| 夹具 | sha256[:16] |
|---|---|
| fixtures/redteam.md | `8fff79fe88b4b6e5` |
| fixtures/benign.md | `add13fd8929dc7cf` |
| fixtures/attack.md | `c426e396e5854e52` |
| fixtures/x_langs.md | `de0bfeaf55f53323` |

## 检查项

| # | 检查 | 结果 | 明细 | 耗时 |
|---|---|---|---|---|
| C1 | 引擎自测 | PASS | 16 samples / 98 rules / 189 patterns | 213 ms |
| C2 | 双侧回归(20 攻击 0 丢失 / 文档 0 误报) | PASS | 召回丢失=0；文档误报 4→0 | 348 ms |
| C3 | 六套盲测(v2..v7) | PASS |   v7 印尼/越南/希伯来           PASS 8/8（门槛 8/8） ｜ ------------------------------------------------------------ ｜ VERDICT: PASS — 六套盲测全部不低于门槛（多语种召回不倒退） | 2126 ms |
| C4 | v8 盲测(宣称/围栏/攻击) | PASS | A 4/4；B ctx 误报 0/3；C 召回 2/2 | 292 ms |
| C5 | 红队 BLOCK≥18 / REVIEW=0 | PASS | BLOCK=18 REVIEW=0 PASS=1 | 381 ms |
| C6 | 良性文档 BLOCK=0 | PASS | BLOCK=0 REVIEW=1 PASS=5 | 470 ms |
| C7 | 宣称层六类全命中 | PASS | 命中 6 条 ｜ claim_attestation,claim_certification,claim_guarantee,claim_sandbox,claim_superlative,claim_universal_trust | 76 ms |
| C8 | 语料快照在位(≥90 份) | SKIP | SKIP：内部语料未随包发布（防污染），不计入结论 | 0 ms |

## 复跑

```
python verify_all.py
```

退出码 0/1 可直接接 CI；语料缺失记 SKIP，`--require-corpus` 可强制判 FAIL。
