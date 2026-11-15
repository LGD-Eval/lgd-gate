"""凭证 / TLS / 批量删除：三类按"类"覆盖的回归。

2026-11-15 类覆盖矩阵实测（修复前）：
  硬编码凭证 2/10、环境变量外泄 6/8、破坏性删除 6/8、TLS 校验关闭 3/7。
最刺眼的一条：AUTH_PATTERNS 这张表自建立起就没被任何扫描循环引用过——
"我们能检出 verify=False / CERT_NONE" 这条声称，背后是一条没通电的规则。
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import skillgate  # noqa: E402


def _scan_py(tmp_path, code, name="d"):
    root = tmp_path / name
    root.mkdir()
    (root / "demo.py").write_text(code, encoding="utf-8")
    (root / "SKILL.md").write_text("# Demo\n\nA tool.\n", encoding="utf-8")
    return skillgate.scan_skill(str(root))


def _cats(result, cats):
    return [f for f in result.findings if f.category in cats]


# ---------------- C1 硬编码凭证 ----------------
_PROVIDER_SECRETS = [
    ("AWS", "K = 'AKIAIOSFODNN7EXAMPLE'\n"),
    ("GitHub", "T = 'ghp_1234567890abcdefghijklmnopqrstuvwx'\n"),
    ("Slack", "S = 'xoxb-1234567890-abcdefghijkl'\n"),
    ("Google", "G = 'AIzaSyA1234567890abcdefghijklmnopqrstuv'\n"),
    ("Stripe", "S = 'sk_live_1234567890abcdefghij'\n"),
    ("私钥块", "P = '-----BEGIN RSA PRIVATE KEY-----'\n"),
    ("数据库 DSN", "D = 'postgres://admin:hunter2secret@db.internal:5432/prod'\n"),
    ("Azure", "A = 'AccountKey=abcdefghijklmnopqrstuvwxyz123456=='\n"),
]


def test_every_provider_secret_shape_is_detected(tmp_path):
    missed = []
    for i, (name, code) in enumerate(_PROVIDER_SECRETS):
        hits = _cats(_scan_py(tmp_path, code, "s%d" % i), ("credential-leak",))
        if not hits or hits[0].severity != "CRITICAL":
            missed.append(name)
    assert not missed, "以下凭证形态未被判 CRITICAL: " + repr(missed)


def test_env_reference_is_not_a_hardcoded_secret(tmp_path):
    """从环境变量读凭证是安全做法，不能按"硬编码凭证"报。"""
    code = "import os\nK = os.getenv('OPENAI_API_KEY')\n"
    leaks = [f for f in _cats(_scan_py(tmp_path, code), ("credential-leak",))
             if f.severity == "CRITICAL"]
    assert leaks == []


# ---------------- C4 TLS 校验关闭 ----------------
_TLS_OFF = [
    "import requests\nrequests.get('https://a.example', verify=False)\n",
    "import ssl\nctx = ssl._create_unverified_context()\n",
    "import ssl\nctx.verify_mode = ssl.CERT_NONE\n",
    "import ssl\nctx.check_hostname = False\n",
    "const o = {rejectUnauthorized: false}\n",
    "import os\nos.environ['PYTHONHTTPSVERIFY'] = '0'\n",
]


def test_every_tls_disable_shape_is_detected(tmp_path):
    missed = []
    for i, code in enumerate(_TLS_OFF):
        hits = _cats(_scan_py(tmp_path, code, "t%d" % i), ("auth", "network"))
        if not hits:
            missed.append(i)
    assert not missed, "以下 TLS 关闭写法未检出: " + repr(missed)


def test_auth_rule_table_is_actually_wired(tmp_path):
    """死规则表回归：AUTH_PATTERNS 曾经一张表定义完就没人调用。"""
    code = "import requests\nrequests.get('https://a.example', verify=False)\n"
    auth_hits = _cats(_scan_py(tmp_path, code, "wired"), ("auth",))
    assert auth_hits, "AUTH_PATTERNS 又没接进扫描循环"


def test_correct_tls_usage_is_not_flagged(tmp_path):
    code = ("import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
            "ctx.verify_mode = ssl.CERT_REQUIRED\nctx.check_hostname = True\n"
            "import requests\nrequests.get('https://a.example', verify=True)\n")
    assert _cats(_scan_py(tmp_path, code, "ok"), ("auth",)) == []


# ---------------- C3 批量删除 ----------------
def test_glob_plus_delete_across_lines_is_detected(tmp_path):
    """pathlib 的 rglob 循环里 unlink 分两行写，单行正则永远看不到。"""
    code = ("from pathlib import Path\n"
            "for p in Path('.').rglob('*'):\n"
            "    p.unlink()\n")
    assert _cats(_scan_py(tmp_path, code, "glob"), ("filesystem", "dangerous-shell"))


def test_shell_delete_inside_string_is_detected(tmp_path):
    code = ("import subprocess\n"
            "subprocess.run(['powershell','-c','Remove-Item -Recurse -Force C:\\\\Users\\\\*'])\n")
    assert _cats(_scan_py(tmp_path, code, "sh"), ("dangerous-shell",))


def test_glob_enumeration_alone_is_not_flagged(tmp_path):
    """只遍历不删除，不是风险。"""
    code = "import glob\nfor f in glob.glob('*.txt'):\n    print(f)\n"
    assert _cats(_scan_py(tmp_path, code, "only"), ("filesystem", "dangerous-shell")) == []


def test_rule_definitions_do_not_self_match(tmp_path):
    """扫描器扫自己时必须不把规则字面量当成攻击命令（实测曾从 93 掉到 69）。"""
    code = ('DEL = (r"remove-item[^\\n]*-(?:recurse|force)", "HIGH")\n')
    assert _cats(_scan_py(tmp_path, code, "self"), ("dangerous-shell",)) == []
