"""§3bg 守卫：脚本藏在解释器参数里，判定照样成立。

上一站把"命令与目标"折成 token 再判，但只有 token[0] 是 shell 才往里翻。
`python -c` / `node -e` / `perl -e` / `php -r` / `osascript -e` / `pwsh -EncodedCommand`
这些槽位里放破坏性脚本，修前 6/11 是 99/A+ 直通。
"""
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import ast_analyzer as A  # noqa: E402


def _hits(body: str):
    src = "import os, subprocess, sys, shutil\n" + textwrap.dedent(body) + "\n"
    import ast
    tree = ast.parse(src)
    consts, temps, lists = A.collect_consts(tree)
    aliases = A.collect_func_aliases(tree)
    v = A.DangerousCallVisitor()
    v.consts, v.temps, v.lists, v.aliases = consts, temps, lists, aliases
    v.visit(tree)
    return [(f.severity, f.message) for f in v.findings]


BLOCK = [
    ("py_c_rmtree", 'subprocess.run([sys.executable, "-c", "import shutil; shutil.rmtree(\'/\')"])'),
    ("py_c_ossystem", 'subprocess.run(["python3", "-c", "import os; os.system(\'anything\')"])'),
    ("node_e_exec", 'subprocess.run(["node", "-e", "require(\'child_process\').execSync(\'x\')"])'),
    ("node_eval", 'subprocess.run(["node", "--eval", "require(\'fs\').rmSync(\'/\',{recursive:true})"])'),
    ("perl_e", 'subprocess.run(["perl", "-e", "system(\'x\')"])'),
    ("ruby_e", 'subprocess.run(["ruby", "-e", "system(\'x\')"])'),
    ("php_r", 'subprocess.run(["php", "-r", "system(\'x\');"])'),
    ("osascript_e", 'CO = \'do shell script "rm -rf /"\'\nsubprocess.run(["osascript", "-e", CO])'),
    ("pwsh_encoded", 'subprocess.run(["pwsh", "-EncodedCommand", "JABjAD0A"])'),
    ("nested_shell_py", 'subprocess.run(["bash", "-c", "python3 -c \'import shutil; shutil.rmtree(1)\'"])'),
    ("var_interp", 'PY = "python3"\nCODE = "import shutil; shutil.rmtree(\'/var/lib\')"\nsubprocess.run([PY, "-c", CODE])'),
]

BENIGN = [
    ("py_c_math", 'subprocess.run(["python", "-c", "print(1+1)"])'),
    ("node_e_log", 'subprocess.run(["node", "-e", "console.log(1+1)"])'),
    ("py_m_pip", 'subprocess.run(["python", "-m", "pip", "install", "-e", "."])'),
    ("py_m_http", 'subprocess.run(["python", "-m", "http.server"])'),
    ("node_file", 'subprocess.run(["node", "scripts/build.js"])'),
    ("bash_c_git", 'subprocess.run(["bash", "-c", "git status"])'),
]


def test_inline_destructive_is_judged():
    for name, body in BLOCK:
        hits = _hits(body)
        assert any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 没判出来：%s" % (name, hits)


def test_inline_benign_is_not_touched():
    for name, body in BENIGN:
        hits = _hits(body)
        assert not any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 被误杀：%s" % (name, hits)


def test_module_flag_is_not_inline_code():
    """`python -m pip` 是模块入口，不是内联脚本——不能拿 -c 的规则打它。"""
    assert A._inline_flag_for("python") == {"-c"}
    assert "-m" not in A._inline_flag_for("python")


def test_sys_executable_counts_as_interpreter():
    """`[sys.executable, "-c", …]` 折不出 token 就等于永远打不开脚本。"""
    import ast
    expr = ast.parse("sys.executable").body[0].value
    assert A._fold_str(expr, {}) == "python"


def test_encoded_command_is_disclosed_not_guessed():
    """编码命令读不出来：判 HIGH 披露，不许假装"看过内容"。"""
    hits = _hits('subprocess.run(["pwsh", "-EncodedCommand", "JABjAD0A"])')
    assert any(sev == "HIGH" and "编码命令" in msg for sev, msg in hits), hits


def test_plain_powershell_command_still_works():
    """补了内联槽位，不能把原来的 shell 包装判定打坏。"""
    hits = _hits('subprocess.run(["powershell", "-Command", "Remove-Item -Recurse -Force /etc"])')
    assert any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), hits
