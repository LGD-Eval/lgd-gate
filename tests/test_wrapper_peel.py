"""§3bi 守卫：真正的命令未必是 token[0]。

`sudo rm …` / `env X=1 …` / `timeout 5 …` / `nice -n 19 …` / `nohup …` /
`xargs …` / `find / -exec … {} +` / `parallel … ::: /`：每套一层包装，
判定就看不到真正的命令。GTFOBins 把 env/sudo 单列为"能执行任意命令"的
提权面——静态判据里同样不能当"无害前缀"跳过。
"""
import ast
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import ast_analyzer as A  # noqa: E402


def _scan(body: str):
    src = "import os, subprocess, sys, shutil\n" + textwrap.dedent(body) + "\n"
    tree = ast.parse(src)
    consts, temps, lists = A.collect_consts(tree)
    aliases = A.collect_func_aliases(tree)
    v = A.DangerousCallVisitor()
    v.consts, v.temps, v.lists, v.aliases = consts, temps, lists, aliases
    v.visit(tree)
    return [(f.severity, f.message) for f in v.findings]


BLOCK = [
    ("sudo_rm", 'subprocess.run(["sudo", "rm", "-r", "-f", "/"])\n'),
    ("env_rm", 'subprocess.run(["env", "PATH=/usr/bin", "rm", "-r", "-f", "/etc"])\n'),
    ("timeout_dd", 'subprocess.run(["timeout", "5", "dd", "of=/dev/sda", "if=/dev/zero"])\n'),
    ("nice_rm", 'subprocess.run(["nice", "-n", "19", "rm", "-r", "-f", "/var"])\n'),
    ("stdbuf_rm", 'subprocess.run(["stdbuf", "-o0", "rm", "-r", "-f", "/usr"])\n'),
    ("nohup_mkfs", 'subprocess.run(["nohup", "mkfs.ext4", "/dev/sda1"])\n'),
    ("xargs_rm", 'subprocess.run(["xargs", "rm", "-r", "-f", "/"])\n'),
    ("find_exec_rm", 'subprocess.run(["find", "/", "-exec", "rm", "-r", "-f", "{}", "+"])\n'),
    ("parallel_rm", 'subprocess.run(["parallel", "rm", "-r", "-f", ":::", "/"])\n'),
    ("watch_dd", 'subprocess.run(["watch", "dd", "of=/dev/sda", "if=/dev/zero"])\n'),
    ("sudo_wipefs", 'subprocess.run(["sudo", "wipefs", "-a", "/dev/sda"])\n'),
    ("nested_sudo_sh", 'subprocess.run(["sudo", "sh", "-c", "rm -r -f /"])\n'),
]

BENIGN = [
    ("xargs_grep", 'subprocess.run(["xargs", "grep", "-l", "TODO"])\n'),
    ("find_exec_wc", 'subprocess.run(["find", ".", "-name", "*.py", "-exec", "wc", "-l", "{}", "+"])\n'),
    ("timeout_pytest", 'subprocess.run(["timeout", "30", "pytest", "-q"])\n'),
    ("env_python", 'subprocess.run(["env", "PATH=/usr/bin", "python3", "-V"])\n'),
    ("nice_make", 'subprocess.run(["nice", "make", "-j4"])\n'),
    ("sudo_systemctl", 'subprocess.run(["sudo", "systemctl", "status", "nginx"])\n'),
    ("watch_git", 'subprocess.run(["watch", "git", "status"])\n'),
    ("busybox_ls", 'subprocess.run(["busybox", "ls", "-l", "/"])\n'),
]


def test_wrapped_destructive_commands_are_judged():
    for name, body in BLOCK:
        hits = _scan(body)
        assert any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 没判出来：%s" % (name, hits)


def test_wrapped_benign_commands_are_not_punished():
    for name, body in BENIGN:
        hits = _scan(body)
        assert not any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 被误杀：%s" % (name, hits)


def test_combined_short_flag_is_a_flag():
    """`stdbuf -o0`：-o0 是开关，不是命令。按 _FLAG_RE 卡字母会把 -o0 当命令。"""
    inner = A._unwrap_wrapper(["stdbuf", "-o0", "rm", "-r", "-f", "/usr"])
    assert inner and inner[0] == "rm", inner


def test_find_exec_target_comes_from_search_path():
    """`find / -exec rm … {} +`：{} 丢掉之后删除目标就是搜索路径。"""
    inner = A._unwrap_wrapper(["find", "/", "-exec", "rm", "-r", "-f", "{}", "+"])
    assert inner and inner[-1] == "/", inner


def test_parallel_puts_command_before_separator():
    """`parallel rm -r -f ::: /`：命令在 ::: 之前，参数在之后，要拼回去。"""
    inner = A._unwrap_wrapper(["parallel", "rm", "-r", "-f", ":::", "/"])
    assert inner and inner[0] == "rm" and inner[-1] == "/", inner


def test_env_is_not_a_harmless_prefix():
    """GTFOBins：env 能执行任意命令，不能当无害前缀放过。"""
    assert A._unwrap_wrapper(["env", "A=1", "bash", "-c", "id"])[0] == "bash"


def test_no_wrapper_returns_none_so_original_path_runs():
    """普通命令不该被剥：返回 None，让原有分支继续判。"""
    assert A._unwrap_wrapper(["git", "status"]) is None
    assert A._unwrap_wrapper(["python", "-c", "print(1)"]) is None
