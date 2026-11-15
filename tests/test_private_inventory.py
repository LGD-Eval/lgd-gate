"""私有包清单核对的口径：清单由使用者提供，占用情况本引擎看不到。

dependency confusion 要成立，需要两件事同时为真：
  1. 这个包名是我私有的（只能使用者告诉我）
  2. 同名包在公开 registry 上能被别人发布并更优先解析（要联网查，本引擎不做）
所以本模块只判 1 成立时"它被当成公开名声明了"这一形状，报 LOW 并写明需 registry 侧核对。
"""
import json
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


def _hits(skill_dir, category="dependency-name"):
    return [f for f in skillgate.scan_skill(str(skill_dir)).findings
            if f.category == category]


INV = json.dumps({"names": ["acme-utils"], "scopes": ["@acme"]})


def test_private_name_declared_bare_is_flagged(tmp_path):
    skill = _skill(tmp_path / "s", {
        "private-packages.json": INV,
        "package.json": '{"name":"t","dependencies":{"acme-utils":"1.0.0"}}',
    })
    hits = [h for h in _hits(skill) if "私有包" in h.message]
    assert hits and hits[0].severity == "LOW", [f.message for f in _hits(skill)]
    assert "registry" in hits[0].message and "抢注" in hits[0].message, hits[0].message


def test_scoped_private_name_is_not_flagged(tmp_path):
    """@acme/acme-utils 是正确写法：scope 已声明，不该报。"""
    skill = _skill(tmp_path / "s", {
        "private-packages.json": INV,
        "package.json": '{"name":"t","dependencies":{"@acme/acme-utils":"1.0.0"}}',
    })
    assert not [h for h in _hits(skill) if "私有包" in h.message]


def test_without_inventory_nothing_is_claimed(tmp_path):
    """没有清单就没有立场：不能凭空说某个包是私有的。"""
    skill = _skill(tmp_path / "s", {"package.json": '{"name":"t","dependencies":{"acme-utils":"1.0.0"}}'})
    assert not [h for h in _hits(skill) if "私有包" in h.message]


def test_broken_inventory_is_reported_not_ignored(tmp_path):
    """清单坏了要说出来，否则等于静默跳过了一个检查。"""
    skill = _skill(tmp_path / "s", {
        "private-packages.json": "{not json",
        "package.json": '{"name":"t","dependencies":{"acme-utils":"1.0.0"}}',
    })
    hits = [h for h in _hits(skill) if "private-packages" in h.message]
    assert hits and hits[0].severity == "LOW", [f.message for f in _hits(skill)]
    assert "未做" in hits[0].message


def test_pypi_private_name_is_flagged(tmp_path):
    skill = _skill(tmp_path / "s", {
        "private-packages.json": INV,
        "requirements.txt": "acme-utils==1.0.0\n",
    })
    hits = [h for h in _hits(skill) if "私有包" in h.message]
    assert hits, [f.message for f in _hits(skill)]
    assert "acme-utils" in hits[0].message
