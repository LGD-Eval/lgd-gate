"""Tier 契约测试：MIGRATION.md、action.yml、evaluate.py 三处必须说同一件事。

存在原因：`tier` 从"权限阶梯 L0–L5"改成"风险档位 T0–T5"是破坏性变更。
破坏性变更最容易出的错不是代码算错，而是三处文本各说一套——文档还在讲 L0 免审批、
action.yml 的描述还在讲 L0-L5、代码已经换成 T。这个测试把三处绑在一起。
"""
import os
import re

import evaluate

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_MAP_ROW = re.compile(
    r"\|[^|]*\|\s*`(L\d)`\s*\|[^|]*\|\s*`(T\d)`\s*\|")


def _read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


def _migration_rows():
    return _MAP_ROW.findall(_read("MIGRATION.md"))


def test_migration_table_covers_all_six_tiers():
    rows = _migration_rows()
    assert rows == [("L0", "T0"), ("L1", "T1"), ("L2", "T2"),
                    ("L3", "T3"), ("L4", "T4"), ("L5", "T5")], rows


def _score_ranges():
    """从 MIGRATION.md 表格首列解析每个档位的分数区间。"""
    out = []
    for line in _read("MIGRATION.md").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 5 or "`T" not in cells[3]:
            continue
        rng = cells[0].replace("`", "").replace("\u2013", "-")
        if rng.startswith("\u2265") or rng.startswith("≥"):
            lo = int(rng.lstrip("≥ ").strip())
            out.append((lo, 100, cells[3].strip("`")))
        else:
            lo, hi = [int(x) for x in rng.split("-")]
            out.append((lo, hi, cells[3].strip("`")))
    return out


def test_documented_ranges_match_code():
    for lo, hi, tier in _score_ranges():
        for score in {lo, hi, (lo + hi) // 2}:
            got = evaluate.risk_tier_for(score).split()[0]
            assert got == tier, "%d 分：文档说 %s，代码给 %s" % (score, tier, got)


def test_action_declares_risk_tier_and_never_grants():
    body = _read("action.yml")
    assert "risk_tier:" in body
    assert "authorization_status=NOT_GRANTED" in body
    assert "::warning::" in body and "MIGRATION.md" in body
    # 旧阶梯的语义不得再出现在 action.yml 里
    assert "L0 免审批" not in body
    assert "execution tier (L0-L5)" not in body


def test_readme_does_not_reissue_permission():
    body = _read("README.md")
    for bad in ("L0 免审批", "免审批直接执行", "分数决定权限"):
        assert bad not in body, "README.md 仍含旧表述：%s" % bad


def test_deprecation_schedule_is_anchored_to_publication():
    """排期不能挂在"今天"，只能挂发布日——否则写下的日期是假的。"""
    body = _read("MIGRATION.md")
    for milestone in ("`W`", "`W+90d`", "`W+180d`"):
        assert milestone in body, "MIGRATION.md 缺少里程碑 %s" % milestone
    assert "publication" in body.lower() or "发布日" in body


def test_release_notes_exist_and_are_marked_draft():
    """发布说明必须先成稿；未获批准前不得声称已发布。"""
    path = os.path.join(HERE, "docs", "RELEASE_NOTES_v2.0.0_DRAFT.md")
    assert os.path.exists(path), "缺少 v2.0.0 发布说明草稿"
    body = open(path, encoding="utf-8").read()
    assert "DRAFT" in body
    # 必须点明旧版本曾公开声称分数决定权限，并撤回这句
    assert "v1.1.0" in body
    assert "retract" in body.lower() or "撤回" in body


def test_amendment_exists_and_retracts_the_public_claim():
    """已发布的 v1.1.0 正文承诺过"分数映射执行档位"，更正必须成文。"""
    path = os.path.join(HERE, "docs", "AMENDMENT_v1.1.0.md")
    assert os.path.exists(path), "缺少 v1.1.0 更正说明"
    body = open(path, encoding="utf-8").read()
    assert "free-run" in body and "3bff151" in body
    # 更正范围必须点明 v1 冻结、不强推——读者要能判断自己装的是哪一版
    assert "frozen" in body.lower() or "冻结" in body
    # 未获批准前不得声称已发布
    assert "DRAFT" in body


def test_readme_pin_matches_the_published_major():
    """README 里的 @vN 必须指向已存在的标签；v2 未发布前仍应是 @v1。"""
    body = _read("README.md")
    assert "LGD-Eval/lgd-gate@v1" in body
    assert "LGD-Eval/lgd-gate@v2" not in body, (
        "v2.0.0 标签尚未发布，README 不应提前指向 @v2（会 404）"
    )
