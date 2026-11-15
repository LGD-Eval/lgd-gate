"""§3bj 守卫：破坏不止删除。

MITRE ATT&CK TA0040：T1485 Data Destruction（清零、覆写、删库）、T1490 Inhibit
System Recovery（删卷影/删备份目录）。GTFOBins 把 shred 列为"能毁本地文件"、
chmod 列为提权面。判据只盯 rm 时，这些全部从旁边走过去。
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
    src = "import os, subprocess, sys, shutil, sqlite3\n" + textwrap.dedent(body) + "\n"
    tree = ast.parse(src)
    consts, temps, lists = A.collect_consts(tree)
    aliases = A.collect_func_aliases(tree)
    v = A.DangerousCallVisitor()
    v.consts, v.temps, v.lists, v.aliases = consts, temps, lists, aliases
    v.visit(tree)
    return [(f.severity, f.message) for f in v.findings]


BLOCK = [
    ("truncate_system", 'subprocess.run(["truncate", "-s0", "/etc/passwd"])\n'),
    ("truncate_log", 'subprocess.run(["truncate", "-s", "0", "/var/log/auth.log"])\n'),
    ("shred_secure", 'subprocess.run(["shred", "-u", "/etc/shadow"])\n'),
    ("shred_zero", 'subprocess.run(["shred", "-n", "3", "-z", "/var/log/syslog"])\n'),
    ("chmod_recursive_zero", 'subprocess.run(["chmod", "-R", "000", "/"])\n'),
    ("chmod_shadow", 'subprocess.run(["chmod", "000", "/etc/shadow"])\n'),
    ("chown_system", 'subprocess.run(["chown", "-R", "nobody", "/etc"])\n'),
    ("icacls_reset", 'subprocess.run(["icacls", "C:\\\\", "/reset", "/T"])\n'),
    ("mv_system", 'subprocess.run(["mv", "/etc/passwd", "/tmp/x"])\n'),
    ("userdel", 'subprocess.run(["userdel", "-r", "root"])\n'),
    ("net_user_delete", 'subprocess.run(["net", "user", "Administrator", "/delete"])\n'),
    ("crontab_remove", 'subprocess.run(["crontab", "-r"])\n'),
    ("schtasks_delete", 'subprocess.run(["schtasks", "/delete", "/tn", "*", "/f"])\n'),
    ("vssadmin_shadows", 'subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"])\n'),
    ("wbadmin_catalog", 'subprocess.run(["wbadmin", "delete", "catalog", "-quiet"])\n'),
    ("git_reset_hard", 'subprocess.run(["git", "reset", "--hard", "origin/main"])\n'),
    ("git_clean", 'subprocess.run(["git", "clean", "-xfd"])\n'),
    ("sql_drop_database", 'sqlite3.connect("app.db").execute("DROP DATABASE prod")\n'),
    ("sql_truncate_table", 'sqlite3.connect("app.db").execute("TRUNCATE TABLE users")\n'),
]

BENIGN = [
    ("chmod_plus_x", 'subprocess.run(["chmod", "+x", "./run.sh"])\n'),
    ("chmod_readonly", 'subprocess.run(["chmod", "644", "README.md"])\n'),
    ("move_file", 'subprocess.run(["mv", "a.txt", "b.txt"])\n'),
    ("git_status", 'subprocess.run(["git", "status"])\n'),
    ("crontab_list", 'subprocess.run(["crontab", "-l"])\n'),
    ("vssadmin_list", 'subprocess.run(["vssadmin", "list", "shadows"])\n'),
    ("sql_select", 'sqlite3.connect("app.db").execute("SELECT * FROM users")\n'),
    ("truncate_grow", 'subprocess.run(["truncate", "--size=+1M", "./data.bin"])\n'),
    ("chown_app_dir", 'subprocess.run(["chown", "app:app", "./dist/bundle.js"])\n'),
]


def test_destructive_verbs_are_judged():
    for name, body in BLOCK:
        hits = _scan(body)
        assert any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 没判出来：%s" % (name, hits)


def test_benign_near_misses_are_not_punished():
    for name, body in BENIGN:
        hits = _scan(body)
        assert not any(sev in ("CRITICAL", "HIGH") for sev, _ in hits), "%s 被误杀：%s" % (name, hits)


def test_truncate_grow_is_not_destroy():
    """--size=+1M 是把文件变长，不毁内容。"""
    assert A.destructive_tokens(["truncate", "--size=+1M", "./data.bin"]) is None


def test_chmod_zero_needs_zero_mode():
    """+x / 644 是正常权限设置，不是清零。"""
    assert A.destructive_tokens(["chmod", "+x", "./run.sh"]) is None
    assert A.destructive_tokens(["chmod", "000", "/etc/shadow"]) is not None


def test_move_only_when_source_is_system_path():
    assert A.destructive_tokens(["mv", "a.txt", "b.txt"]) is None
    sev, _ = A.destructive_tokens(["mv", "/etc/passwd", "/tmp/x"])
    assert sev == "CRITICAL"


def test_crontab_list_is_not_remove():
    assert A.destructive_tokens(["crontab", "-l"]) is None
    sev, _ = A.destructive_tokens(["crontab", "-r"])
    assert sev == "HIGH"


def test_drop_database_outranks_drop_table():
    """删库（DROP DATABASE）必须比 DROP TABLE 更重。"""
    sev_db, _ = A.destructive_tokens(["sqlite3", "x", "DROP DATABASE prod"])
    sev_tb, _ = A.destructive_tokens(["sqlite3", "x", "DROP TABLE users"])
    assert sev_db == "CRITICAL" and sev_tb == "HIGH"
