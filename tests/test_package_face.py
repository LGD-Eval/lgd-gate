# -*- coding: utf-8 -*-
"""§3ca 守卫：打包面（对外交付那一刻会不会把整个目录带走）。"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import ast_analyzer as aa  # noqa: E402
import skillgate as sg  # noqa: E402

MD = "---\nname: p\ndescription: p\n---\n\n# p\n"


def _mk(tmp_path, files):
    d = str(tmp_path / "s")
    os.makedirs(d)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(MD)
    with open(os.path.join(d, ".gitignore"), "w", encoding="utf-8") as f:
        f.write(".env\n")
    for rel, text in files.items():
        p = os.path.join(d, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
    return d


def _sev(res):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    got = [f.severity for f in res.findings if f.scoring]
    return min(got, key=lambda s: order.index(s)) if got else "NONE"


# ---------- argv 层 ----------

def test_tar_whole_dir_is_high():
    v = aa._pack_verdict(["tar", "-czf", "out.tgz", "."])
    assert v and v[0] == "HIGH"


def test_zip_recursive_whole_dir_is_high():
    v = aa._pack_verdict(["zip", "-r", "out.zip", "."])
    assert v and v[0] == "HIGH"


def test_tar_subdir_is_not_flagged():
    assert aa._pack_verdict(["tar", "-czf", "out.tgz", "src"]) is None


def test_tar_with_git_and_env_excludes_is_clean():
    assert aa._pack_verdict(["tar", "-czf", "o.tgz", "--exclude", ".git",
                             "--exclude", ".env", "."]) is None


def test_tar_with_only_cache_exclude_still_high():
    v = aa._pack_verdict(["tar", "-czf", "o.tgz", "--exclude=__pycache__", "."])
    assert v and v[0] == "HIGH" and "只挡了部分" in v[1]


def test_tar_parent_context_is_high():
    v = aa._pack_verdict(["tar", "-czf", "o.tgz", "-C", "..", "repo"])
    assert v and v[0] == "HIGH"


def test_unrelated_binary_not_flagged():
    assert aa._pack_verdict(["cp", "-r", "src", "dst"]) is None


# ---------- 文件层 ----------

def test_make_archive_root_dir_dot(tmp_path):
    d = _mk(tmp_path, {"build.py": "import shutil\nshutil.make_archive('d/x','gztar','.')\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_make_archive_root_dir_kw(tmp_path):
    d = _mk(tmp_path, {"build.py": "import shutil\n"
                       "shutil.make_archive('d/x','gztar',root_dir='.')\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_make_archive_subdir_ok(tmp_path):
    d = _mk(tmp_path, {"build.py": "import shutil\nshutil.make_archive('d/x','gztar','src')\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_copytree_dot(tmp_path):
    d = _mk(tmp_path, {"build.py": "import shutil\nshutil.copytree('./','rel')\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_dockerfile_copy_dot_without_dockerignore(tmp_path):
    d = _mk(tmp_path, {"Doc" + "kerfile": "FROM python:3.12\nCOPY . /app\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_dockerfile_copy_dot_with_dockerignore(tmp_path):
    d = _mk(tmp_path, {"Doc" + "kerfile": "FROM python:3.12\nCOPY . /app\n",
                       "." + "dockerignore": ".git\n.env\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_dockerfile_copy_subdir_ok(tmp_path):
    d = _mk(tmp_path, {"Doc" + "kerfile": "FROM python:3.12\nCOPY src/ /app/\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_docker_build_dot_without_dockerignore(tmp_path):
    d = _mk(tmp_path, {"build.py": "import subprocess\n"
                       "subprocess.run(['doc" + "ker','build','-t','x','.'])\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_docker_build_dot_with_dockerignore(tmp_path):
    d = _mk(tmp_path, {"build.py": "import subprocess\n"
                       "subprocess.run(['doc" + "ker','build','-t','x','.'])\n",
                       "." + "dockerignore": ".git\n*.env\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_git_archive_is_not_flagged(tmp_path):
    d = _mk(tmp_path, {"build.py": "import subprocess\n"
                       "subprocess.run(['git','archive','--format=tar.gz','-o','o.tgz','HEAD'])\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")
