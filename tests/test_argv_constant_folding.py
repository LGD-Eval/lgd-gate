"""§3bf 守卫：把字面量藏进变量，判定必须照样成立。

上一站留了一句"argv 里有变量就不判"。这站把它做成攻击：目标变量、命令列表
变量、函数内变量、字符串拼接、f-string、链式别名、spawn 参数——七种藏法
修前全部 96–99/A+，等于白送一条绕过后门。
"""
import ast
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import ast_analyzer as A  # noqa: E402

HIDDEN = [
    ("tgt_var", 'TGT = "/"\nsubprocess.run(["rm", "-rf", TGT])'),
    ("cmd_list_var", 'CMD = ["rm", "-rf", "/"]\nsubprocess.run(CMD)'),
    ("cmd_in_func", 'def go():\n    a = ["mkfs.ext4", "/dev/sda1"]\n    subprocess.run(a)'),
    ("concat", 'subprocess.run(["rm", "-rf", "/" + ""])'),
    ("fstring", 'ROOT = "/"\nsubprocess.run(["rm", "-rf", f"{ROOT}"])'),
    ("alias_chain", 'A = "/"\nB = A\nsubprocess.run(["rmdir", "/s", "/q", B])'),
    ("spawn_var", 'CMD = "rm"\nos.spawnlp(0, CMD, CMD, "-rf", "/")'),
    ("emp_var", 'LIB = "/var/lib"\nshutil.rmtree(LIB)'),
]

BENIGN = [
    ("git_var", 'S = "status"\nsubprocess.run(["git", S])'),
    ("build_var", 'D = "build/dist"\nsubprocess.run(["rm", "-rf", D])'),
    ("rmtree_tmp_var", 'D = tempfile.mkdtemp()\nshutil.rmtree(D)'),
    ("unknown_var", 'target = shell_out()\nsubprocess.run(["rm", "-rf", target])'),
    ("func_alias_benign", 'run = subprocess.run\nrun(["git", "status"])'),
]

ALIASES = [
    ("plain_alias", 'run = subprocess.run\nrun(["rm", "-rf", "/"])'),
    ("import_from", 'from subprocess import run as r\nr(["rm", "-rf", "/"])'),
    ("popen_alias", 'from subprocess import Popen\nPopen(["mkfs.ext4", "/dev/sda1"])'),
]


def _hits(body: str):
    src = textwrap.dedent(
        "import os, subprocess, shutil, tempfile\n"
        "def shell_out():\n    return '/'\n" + body + "\n")
    tree = ast.parse(src)
    consts, temps, lists = A.collect_consts(tree)
    aliases = A.collect_func_aliases(tree)
    v = A.DangerousCallVisitor()
    v.consts, v.temps, v.lists, v.aliases = consts, temps, lists, aliases
    v.visit(tree)
    return [(f.severity, f.message) for f in v.findings]


def test_hidden_forms_are_judged():
    for name, body in HIDDEN:
        hits = _hits(body)
        assert any(sev == "CRITICAL" for sev, _ in hits), "%s 没判出来：%s" % (name, hits)


def test_benign_forms_stay_clean():
    for name, body in BENIGN:
        hits = _hits(body)
        assert not any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 被误杀：%s" % (name, hits)


def test_function_aliases_are_translated():
    """`run = subprocess.run` / `from subprocess import run as r` 不能让判据失明。"""
    for name, body in ALIASES:
        hits = _hits(body)
        assert any(sev == "CRITICAL" for sev, _ in hits), "%s 没判出来：%s" % (name, hits)


def test_conflicting_assignment_is_not_guessed():
    """同名不同值 → 判为不可知，不许猜（猜错就是误杀或漏放）。"""
    body = ('D = "build/x"\nrun(["rm", "-rf", D])\nD = "/"\nrun(["rm", "-rf", D])')
    consts, _, lists = A.collect_consts(ast.parse(textwrap.dedent(
        "import subprocess\nrun = subprocess.run\n" + body + "\n")))
    assert "D" not in consts, consts


def test_folding_is_per_file():
    """常量表按文件构建：一个文件里的名字不得到另一个文件里继续生效。"""
    body = 'CMD = ["rm", "-rf", "/"]\nsubprocess.run(CMD)'
    hits = _hits(body)
    assert any(sev == "CRITICAL" for sev, _ in hits)


def test_fstring_with_variable_is_not_folded():
    """f-string 里含真变量时应放弃折叠（折不出来才安全）。"""
    body = 'ROOT = input()\nrun(["rm", "-rf", f"{ROOT}"])'
    consts, _, lists = A.collect_consts(ast.parse(
        textwrap.dedent("import subprocess\nrun = subprocess.run\n" + body + "\n")))
    assert "ROOT" not in consts
