"""两处良性误报的回归钉（D3 递归删除、D4 依赖版本假精确）。

修复前实测：
  priv-rm-ben（有 startswith 路径守卫）→ 69/C
  benign-js-fetch（requirements.txt 写 `requests>=2.31`）→ 69/C

第二条的根因值得单独记：`>=` 被当成 `==latest` 送去 OSV，回来的漏洞
被报成"requests==latest 存在 XX 漏洞"——一个不存在的版本号。
假精确比漏报更难被使用者识破，因为它长得像结论。

这里同时钉住反向：没守卫的递归删除必须仍然判得重。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import skillgate  # noqa: E402

GUARDED = '''"""Clean build artefacts. Refuses to leave the working directory."""
import os
import shutil

ROOT = "./tmp"


def clean():
    target = os.path.abspath(ROOT)
    cwd = os.path.abspath(".")
    if not target.startswith(cwd + os.sep):
        raise SystemExit("refusing to delete outside the working directory")
    if os.path.isdir(target):
        shutil.rmtree(target)
'''

UNGUARDED = '''"""Clean build artefacts."""
import shutil


def clean(path):
    shutil.rmtree(path)
'''


def _skill(root, py_src):
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text("# Cleaner\n\nRemoves build output.\n", encoding="utf-8")
    (root / "scripts" / "clean.py").write_text(py_src, encoding="utf-8")
    return root


def test_guarded_rmtree_is_downgraded(tmp_path):
    _skill(tmp_path, GUARDED)
    hits = [f for f in skillgate.scan_skill(str(tmp_path)).findings
            if "递归删除" in f.message]
    assert hits, "递归删除本身仍应被记录（降级不是免报）"
    assert hits[0].severity == "LOW", hits[0].severity
    assert "路径守卫" in hits[0].message


def test_unguarded_rmtree_stays_severe(tmp_path):
    """没有守卫的递归删除必须仍然判得重，否则这次改动就是给自己开后门。"""
    _skill(tmp_path, UNGUARDED)
    hits = [f for f in skillgate.scan_skill(str(tmp_path)).findings
            if "递归删除" in f.message]
    assert hits and hits[0].severity == "HIGH", [(f.severity, f.message) for f in hits]


def test_version_range_is_not_reported_as_a_pinned_vulnerability(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "SKILL.md").write_text("# Pinger\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")
    hits = [f for f in skillgate.scan_skill(str(tmp_path)).findings
            if f.category in ("dependency-vuln", "dependency-scan")]
    assert hits, "范围约束至少应有一条说明，而不是沉默"
    assert hits[0].severity == "MEDIUM", hits[0].severity
    assert "无法判定" in hits[0].message
    assert "latest" not in hits[0].message, "不得再造一个不存在的版本号"
