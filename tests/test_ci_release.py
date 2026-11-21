# -*- coding: utf-8 -*-
"""§3cb 守卫：CI 侧发布出口（artifact / npm pack / sdist 清单 / release 资产）。"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import skillgate as sg  # noqa: E402

MD = "---\nname: c\ndescription: c\n---\n\n# c\n"
HEAD = ("name: rel\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n")


def _mk(tmp_path, files):
    d = str(tmp_path / "s")
    os.makedirs(d)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(MD)
    if ".gitignore" not in files:
        with open(os.path.join(d, ".gitignore"), "w", encoding="utf-8") as f:
            f.write(".env\n")
    for rel, text in files.items():
        p = os.path.join(d, *rel.split("/"))
        if os.path.dirname(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
    return d


def _sev(res):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    got = [f.severity for f in res.findings if f.scoring]
    return min(got, key=lambda s: order.index(s)) if got else "NONE"


WF = ".github/workflows/rel.yml"


def test_artifact_whole_workspace_is_high(tmp_path):
    d = _mk(tmp_path, {WF: HEAD + "      - uses: actions/upload-artifact@v4\n"
                               "        with:\n          name: all\n          path: .\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_artifact_workspace_expression_is_high(tmp_path):
    d = _mk(tmp_path, {WF: HEAD + "      - uses: actions/upload-artifact@v4\n"
                               "        with:\n          name: all\n"
                               "          path: ${{ github.workspace }}\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_artifact_dist_dir_is_clean(tmp_path):
    d = _mk(tmp_path, {WF: HEAD + "      - uses: actions/upload-artifact@v4\n"
                               "        with:\n          name: d\n          path: dist/\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_artifact_with_negation_is_clean(tmp_path):
    d = _mk(tmp_path, {WF: HEAD + "      - uses: actions/upload-artifact@v4\n"
                               "        with:\n          name: all\n"
                               "          path: |\n            .\n"
                               "            !**/.env\n            !**/.git/**\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_npm_pack_without_files_is_high(tmp_path):
    d = _mk(tmp_path, {"package.json": '{"name":"x","version":"1.0.0"}\n',
                       "." + "npmignore": "",
                       WF: HEAD + "      - run: npm pack\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_npm_pack_with_files_field_is_clean(tmp_path):
    d = _mk(tmp_path, {"package.json": '{"name":"x","version":"1.0.0","files":["dist"]}\n',
                       WF: HEAD + "      - run: npm pack\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_npm_pack_falls_back_to_covering_gitignore(tmp_path):
    d = _mk(tmp_path, {"package.json": '{"name":"x","version":"1.0.0"}\n',
                       WF: HEAD + "      - run: npm pack\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_manifest_graft_root_is_high(tmp_path):
    d = _mk(tmp_path, {"MANIFEST.in": "graft .\n", WF: HEAD + "      - run: python -m build\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_manifest_include_env_is_high(tmp_path):
    d = _mk(tmp_path, {"MANIFEST.in": "include .env\n", WF: HEAD + "      - run: python -m build\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_manifest_prune_env_is_clean(tmp_path):
    d = _mk(tmp_path, {"MANIFEST.in": "prune .env\nexclude .env\n",
                       WF: HEAD + "      - run: python -m build\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_manifest_package_specific_is_clean(tmp_path):
    d = _mk(tmp_path, {"MANIFEST.in": "recursive-include lgd_eval *.py\n",
                       WF: HEAD + "      - run: python -m build\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_gh_release_whole_dir_is_high(tmp_path):
    d = _mk(tmp_path, {WF: HEAD + "      - run: gh release create v1 .\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_gh_release_single_asset_is_clean(tmp_path):
    d = _mk(tmp_path, {WF: HEAD + "      - run: gh release create v1 dist/x.tgz\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_workflow_outside_github_dir_is_ignored(tmp_path):
    d = _mk(tmp_path, {"ci/rel.yml": HEAD + "      - uses: actions/upload-artifact@v4\n"
                                           "        with:\n          path: .\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_manifest_risky_detector_units():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "MANIFEST.in")
    with open(p, "w", encoding="utf-8") as f:
        f.write("graft .\n")
    assert sg._manifest_risky(sg.Path(p)) is not None
    with open(p, "w", encoding="utf-8") as f:
        f.write("include README.md\n")
    assert sg._manifest_risky(sg.Path(p)) is None

def test_non_artifact_path_step_is_ignored(tmp_path):
    """同一工作流里别的 action 也有 `path:` 输入时，不能当成"上传整个工作区"。"""
    d = _mk(tmp_path, {WF: HEAD +
                       "      - uses: LGD-Eval/lgd-gate@main\n"
                       "        with:\n          path: .\n          threshold: '60'\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")