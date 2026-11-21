"""仿名（typosquatting）提示的口径：只提示，不定罪。

公开研究口径：
  · Levenshtein 1–2 是主流启发式，但已知误报高；40 个已知 typosquat 中
    18 个距离 ≤2（arXiv 2502.20528 综述）。
  · 子集型（把长名简化）编辑距离可达 14，只有分词能抓。
  · 依赖混淆的结构性修法是受控 scope + 显式 registry 映射，
    扫描器只能提醒核对来源，不能替代 registry 侧校验。
所以本模块只产出 LOW：名字长得像，不是证据。
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import skillgate  # noqa: E402


def _skill(root, files):
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# Dep Tool\n\nReads data.\n")
    for rel, body in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
    return root


def _name_hits(skill_dir):
    return [f for f in skillgate.scan_skill(str(skill_dir)).findings
            if f.category == "dependency-name"]


def test_edit_distance_one_lookalike_is_flagged_as_low(tmp_path):
    """requsts vs requests：距离 1，只提示，不定罪。"""
    skill = _skill(tmp_path / "s", {"requirements.txt": "requsts==2.31.0\n"})
    hits = _name_hits(skill)
    assert hits and hits[0].severity == "LOW", [(f.severity, f.message) for f in hits]
    assert "requests" in hits[0].message
    assert "不是" in hits[0].message and "registry" in hits[0].message, hits[0].message


def test_real_popular_package_is_not_flagged(tmp_path):
    """真的热门包不该被当成仿冒品——这是最容易自伤的一条。"""
    skill = _skill(tmp_path / "s", {"requirements.txt": "requests==2.31.0\nnumpy==1.26.0\n"})
    assert not _name_hits(skill), [f.message for f in _name_hits(skill)]


def test_visual_substitution_is_caught(tmp_path):
    """l0dash → lodash：数字换字母，规范化后同名。"""
    skill = _skill(tmp_path / "s", {"package.json": '{"name":"t","dependencies":{"l0dash":"4.17.15"}}'})
    hits = _name_hits(skill)
    assert hits and "lodash" in hits[0].message, [f.message for f in hits]


def test_subset_shape_is_caught(tmp_path):
    """子集型：unused-imports ⊂ eslint-plugin-unused-imports（编辑距离 14，分词才抓得到）。"""
    skill = _skill(tmp_path / "s", {"package.json": '{"name":"t","dependencies":{"unused-imports":"1.0.0"}}'})
    hits = _name_hits(skill)
    assert hits and "子集型" in hits[0].message, [f.message for f in hits]


def test_unrelated_short_names_are_not_flagged(tmp_path):
    """短名字不做距离判定：三位以内的名字互相都在距离 1，报了就是噪音。"""
    skill = _skill(tmp_path / "s", {"requirements.txt": "six==1.16.0\nidna==3.0\n"})
    assert not _name_hits(skill), [f.message for f in _name_hits(skill)]


def test_name_hint_never_escalates_severity(tmp_path):
    skill = _skill(tmp_path / "s", {"requirements.txt": "requsts==2.31.0\n"})
    res = skillgate.scan_skill(str(skill))
    assert res.critical_count == 0 and res.high_count == 0, res.findings
