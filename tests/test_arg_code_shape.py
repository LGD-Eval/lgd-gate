"""§3bh 守卫：判据不看程序名，看"参数是不是代码"。

§3bg 把"哪个开关后面是代码"枚举成表；这一站证明枚举注定漏：
`deno eval <CODE>` 是位置参数、`node -p` 不在表里、`awk 'BEGIN{…}'`
整段程序就是第一个位置参数、`sqlite3 :memory: ".shell …"` 也一样。
守的是"形状判据"必须在场，而不是某几个程序名恰好被登记过。
"""
import ast
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import ast_analyzer as A  # noqa: E402


def _hits(body: str):
    src = "import os, subprocess, sys, shutil\n" + textwrap.dedent(body) + "\n"
    tree = ast.parse(src)
    consts, temps, lists = A.collect_consts(tree)
    aliases = A.collect_func_aliases(tree)
    v = A.DangerousCallVisitor()
    v.consts, v.temps, v.lists, v.aliases = consts, temps, lists, aliases
    v.visit(tree)
    return [(f.severity, f.message) for f in v.findings]


# 刻意全都不含 "rm -rf"/"Remove-Item" 这类散文也会出现的词：
# 判据要是靠"好词"撞上，这里一条都不该过。
BLOCK = [
    ("deno_positional",
     'subprocess.run(["deno", "eval", "import {rmSync} from \'node:fs\'; rmSync(\'/var/lib/app\',{recursive:true})"])'),
    ("node_p_flag",
     'subprocess.run(["node", "-p", "require(\'fs\').rmSync(\'/var/lib/app\',{recursive:true})"])'),
    ("awk_program",
     'subprocess.run(["awk", "BEGIN{system(\\"truncate -s0 /etc/passwd\\")}"])\n'),
    ("sqlite_dot_command",
     'subprocess.run(["sqlite3", ":memory:", ".shell dd if=/dev/zero of=/dev/sda"])\n'),
    ("groovy_runtime",
     'subprocess.run(["groovy", "-e", "Runtime.getRuntime().exec(\'dd if=/dev/zero of=/dev/sda\')"])\n'),
    ("expect_spawn",
     'subprocess.run(["expect", "-c", "spawn dd if=/dev/zero of=/dev/sda"])\n'),
    ("perl_unlink",
     'subprocess.run(["perl", "unlink(\'/etc/passwd\')"])\n'),
    ("rscript_unlink",
     'subprocess.run(["Rscript", "-e", "unlink(\'/etc/passwd\')"])\n'),
    ("deno_remove",
     'subprocess.run(["deno", "eval", "Deno.remove(\'/var/lib/app\',{recursive:true})"])\n'),
]

BENIGN = [
    ("git_commit_msg", 'subprocess.run(["git", "commit", "-m", "docs: warn about rm -rf in install scripts"])'),
    ("grep_pattern", 'subprocess.run(["grep", "-rn", "shutil.rmtree(", "--include", "*.py", "scripts"])'),
    ("rg_pattern", 'subprocess.run(["rg", "os.system(", "docs"])'),
    ("echo_text", 'subprocess.run(["echo", "child_process is risky, do not use it"])'),
    ("deno_eval_benign", 'subprocess.run(["deno", "eval", "console.log(1+1)"])'),
    ("awk_print", 'subprocess.run(["awk", "{print $1}", "access.log"])'),
]


def test_code_shaped_args_are_judged():
    for name, body in BLOCK:
        hits = _hits(body)
        assert any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 没判出来：%s" % (name, hits)


def test_text_and_prose_args_are_not_punished():
    for name, body in BENIGN:
        hits = _hits(body)
        assert not any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 被误杀：%s" % (name, hits)


def test_text_only_tools_are_skipped():
    """grep/echo 的位置参数是"要找的东西"，不能当代码判。"""
    for t in ("grep", "rg", "echo", "printf", "findstr"):
        assert t in A.TEXT_ONLY_TOOLS
        assert A._arg_code_verdict([t, "shutil.rmtree("]) is None


def test_shape_judgement_does_not_need_registered_interpreter():
    """`awk` 从没进过内联表，形状判据照样要认。"""
    assert A._inline_flag_for("awk") is None
    assert A._arg_code_verdict(["awk", "BEGIN{system(1)}"]) is not None


def test_registered_table_stays_only_an_accelerator():
    """表里登记的解释器仍要给"无法静态判定"的编码命令披露。"""
    hits = _hits('subprocess.run(["pwsh", "-EncodedCommand", "JABjAD0A"])')
    assert any(sev == "HIGH" and "编码命令" in msg for sev, msg in hits), hits
