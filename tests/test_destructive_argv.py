"""§3be 守卫：判级要看参数，不只看调用了什么。

实测（audit2/probe_destructive_argv.py，修复前）：11 个破坏性 argv 里
9 个拿 99/A+ 直通——`subprocess.run(["rm","-rf","/"])` 与
`subprocess.run(["git","status"])` 同分；反过来 `shutil.rmtree(tempfile.mkdtemp())`
这种良性清理被标签卡在 69/C。两头都错，所以两头都守。
"""
import ast
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import ast_analyzer as A  # noqa: E402

DESTRUCTIVE = [
    ("rm_root", 'subprocess.run(["rm", "-rf", "/"])'),
    ("rm_home", 'subprocess.run(["rm", "-rf", "~/"])'),
    ("rmdir_win", 'subprocess.run(["rmdir", "/s", "/q", "C:\\\\"])'),
    ("del_win", 'subprocess.run(["del", "/f", "/s", "/q", "C:\\\\Users"])'),
    ("mkfs", 'subprocess.run(["mkfs.ext4", "/dev/sda1"])'),
    ("dd", 'subprocess.run(["dd", "if=/dev/zero", "of=/dev/sda"])'),
    ("shutdown", 'subprocess.run(["shutdown", "-h", "now"])'),
    ("shell_wrap", 'subprocess.run(["/bin/sh", "-c", "rm -rf /home"])'),
    ("spawn", 'os.spawnlp(os.P_NOWAIT, "rm", "rm", "-rf", "/")'),
    ("fork_bomb", 'subprocess.run(["bash", "-c", ":(){ :|:& };:"])'),
]

BENIGN = [
    ("git_status", 'subprocess.run(["git", "status"], check=True)'),
    ("pytest", 'subprocess.run(["pytest", "-q"])'),
    ("rm_one_file", 'subprocess.run(["rm", "build/tmp.txt"])'),
    ("rm_rf_local", 'subprocess.run(["rm", "-rf", "build/dist"])'),
    ("pip_install", 'subprocess.run(["pip", "install", "-e", "."])'),
    ("rmtree_tmp", 'shutil.rmtree(tempfile.mkdtemp())'),
]


def _findings(body: str):
    tree = ast.parse(textwrap.dedent("import os, subprocess, shutil, tempfile\n" + body + "\n"))
    return A.analyze_python_tree(tree) if hasattr(A, "analyze_python_tree") else None


def _call_hits(body: str):
    """直接对语法树跑 visitor，返回 (severity, message) 列表。"""
    tree = ast.parse(textwrap.dedent("import os, subprocess, shutil, tempfile\n" + body + "\n"))
    v = A.DangerousCallVisitor()
    v.visit(tree)
    return [(f.severity, f.message) for f in v.findings]


@pytest.mark.parametrize("name,body", DESTRUCTIVE, ids=[d[0] for d in DESTRUCTIVE])
def test_destructive_argv_blocks(name, body):
    hits = _call_hits(body)
    assert hits, "%s 一条没报" % name
    assert any(sev == "CRITICAL" for sev, _ in hits), "%s 报的是 %s，不是 CRITICAL" % (name, hits)


@pytest.mark.parametrize("name,body", BENIGN, ids=[b[0] for b in BENIGN])
def test_benign_argv_not_critical(name, body):
    hits = _call_hits(body)
    assert not any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), \
        "%s 被误杀：%s" % (name, hits)


def test_bare_slash_is_target_not_flag():
    """装置自错第 16 次回归：`/` 曾被 _FLAG_RE 当成开关，目标列表变空、判定静默失效。"""
    assert A.destructive_tokens(["rm", "-rf", "/"])[0] == "CRITICAL"
    assert A.destructive_tokens(["rm", "-rf", "build/dist"]) is None


def test_tempfile_rmtree_is_disclosed_not_blocked():
    assert A.destructive_command(
        ast.parse('shutil.rmtree(tempfile.mkdtemp())').body[0].value, "shutil.rmtree", None
    )[0] == "LOW"
    assert A.destructive_command(
        ast.parse('shutil.rmtree("/var/lib")').body[0].value, "shutil.rmtree", None
    )[0] == "CRITICAL"


def test_variable_argv_is_not_guessed():
    """argv 里有变量时不下结论：仍按披露档（LOW），不假装知道它要删什么。"""
    hits = _call_hits('cmd = ["rm", "x"]\nsubprocess.run(cmd)')
    assert hits and all(sev == "LOW" for sev, _ in hits), hits


def test_real_repo_commands_stay_clean():
    """本仓合法命令不得被新规则拦：git / pytest / node / python。"""
    body = """
subprocess.run(["git", "log", "--oneline"], check=True)
subprocess.run(["pytest", "-q", "tests"])
subprocess.run(["node", "--version"])
"""
    hits = _call_hits(body)
    assert all(sev == "LOW" for sev, _ in hits), hits
