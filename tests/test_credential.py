"""§3bx：凭据与密钥生命周期（credential & key lifecycle）。

修前实测（audit2/probe_credential.py，12 攻击 + 8 良性近亲）：**9/12 漏放**、
1 误杀。拦住的只有三条（写 aws 凭证文件、私钥拷到 /tmp、shell rc 里 export 口令），
其余九条全是 99–100 A+：密钥打进日志、`git credential.helper store`、
token 塞进 remote URL、1024 位 RSA、`openssl genrsa 512`、`ssh -A`、
`mysql -p<口令>`、`pickle.dump(creds)`、写 netrc 只到 MEDIUM。

判据两层：
1. 命令侧 `_credential_verdict`：credential.helper store → HIGH；
   remote URL 带 user:token → CRITICAL；`ssh -A` → HIGH；
   短密钥（<2048 位）→ HIGH；命令行明文口令（`-p<pw>`/`--password=…`）→ HIGH。
2. 内容侧 `_cred_log_findings` / `_cred_write_findings`：把凭据变量打进
   logging/print → HIGH；写 netrc/aws 凭证/git 凭证/pgpass → HIGH；
   把凭据序列化落盘（pickle/json/shelve/torch.save…）→ HIGH。

另有一处**误杀**：`ssh-keygen -f ~/.ssh/id_ed25519` 是生成密钥，文本层按字面路径
判成"访问 SSH 私钥"（69/C）。收口在 scan_skill 末尾按"同一行有 ssh-keygen"压制，
并记一条豁免留痕（waiver），不静默丢弃。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import skillgate as sg

MD = "---\nname: demo\ndescription: demo\n---\n\n# demo\n"


def _skill(tmp_path, name, body):
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(MD, encoding="utf-8")
    (d / "main.py").write_text(body, encoding="utf-8")
    return d


def _sev(d):
    return {f.severity for f in sg.scan_skill(str(d)).findings}


def _msgs(d):
    return [str(f.message) for f in sg.scan_skill(str(d)).findings]


def _hi(d):
    s = _sev(d)
    return "HIGH" in s or "CRITICAL" in s


# ---- 攻击：凭据出口 ----

def test_secret_in_log(tmp_path):
    """把 API key 打进日志：日志会落盘、被收集、被贴进 issue。"""
    d = _skill(tmp_path, "log", """
import logging, os
def run():
    api_key = os.environ.get("API_KEY")
    logging.info("using key %s" % api_key)
""")
    assert _hi(d)
    assert any("日志" in m for m in _msgs(d))


def test_secret_print(tmp_path):
    d = _skill(tmp_path, "pr", """
import os
token = os.environ.get("GH_TOKEN")
print(token)
""")
    assert _hi(d)


def test_secret_in_exception_flatten(tmp_path):
    d = _skill(tmp_path, "exc", """
import logging
def go(secret):
    logging.error("failed with secret=%s", secret)
""")
    assert _hi(d)


# ---- 攻击：凭据落盘 ----

def test_aws_credentials_written(tmp_path):
    d = _skill(tmp_path, "aws", """
import os
def w():
    open(os.path.expanduser("~/.aws/credentials"), "w").write("[default]\\naws_access_key_id=AKIA1\\n")
""")
    assert _hi(d)


def test_netrc_written_is_high(tmp_path):
    """写 netrc 原来只到 MEDIUM（只是"碰到了凭证文件"）；写出来必须是 HIGH。"""
    d = _skill(tmp_path, "netrc", """
import os
def w():
    open(os.path.expanduser("~/.netrc"), "w").write("machine api.example.com login bob password hunter2\\n")
""")
    assert _hi(d)


def test_git_credentials_file(tmp_path):
    d = _skill(tmp_path, "gitc", """
def w():
    open(".git-credentials", "w").write("https://user:token@github.com\\n")
""")
    assert _hi(d)


def test_pickle_credentials(tmp_path):
    """pickle 是可执行格式：口令与一个反序列化执行面被打包在一起。"""
    d = _skill(tmp_path, "pick", """
import pickle
def save(creds):
    pickle.dump(creds, open("creds.pkl", "wb"))
""")
    assert _hi(d)
    assert any("序列化" in m for m in _msgs(d))


def test_shelve_token_store(tmp_path):
    d = _skill(tmp_path, "shv", """
import shelve
def put(api_token):
    db = shelve.open("tokens.db")
    db["t"] = api_token
""")
    assert _hi(d)


# ---- 攻击：命令侧的保管方式 ----

def test_git_credential_helper_store(tmp_path):
    """credential.helper=store：口令明文落盘到 ~/.git-credentials。"""
    d = _skill(tmp_path, "gcs", """
import subprocess
subprocess.run(["git", "config", "--global", "credential.helper", "store"])
""")
    assert _hi(d)


def test_git_remote_with_token(tmp_path):
    d = _skill(tmp_path, "grt", """
import subprocess
subprocess.run(["git", "remote", "set-url", "origin",
                "https://user:ghp_abcdefghij0123456789@github.com/x/y.git"])
""")
    assert "CRITICAL" in _sev(d)


def test_ssh_keygen_short_rsa(tmp_path):
    d = _skill(tmp_path, "kg", """
import subprocess
subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "1024", "-f", "/tmp/k"])
""")
    assert _hi(d)


def test_openssl_short_key(tmp_path):
    d = _skill(tmp_path, "osl", """
import subprocess
subprocess.run(["openssl", "genrsa", "-out", "/tmp/k.pem", "512"])
""")
    assert _hi(d)


def test_ssh_agent_forward(tmp_path):
    d = _skill(tmp_path, "fwd", """
import subprocess
subprocess.run(["ssh", "-A", "build@host", "make"])
""")
    assert _hi(d)


def test_mysql_inline_password(tmp_path):
    d = _skill(tmp_path, "my", """
import subprocess
subprocess.run(["mysql", "-u", "root", "-pS3cr3tPass", "-e", "show databases"])
""")
    assert _hi(d)


def test_shell_rc_export_secret(tmp_path):
    d = _skill(tmp_path, "rc", """
import os
def p():
    open(os.path.expanduser("~/.bashrc"), "a").write("export GITHUB_TOKEN=ghp_abcdefghij0123456789\\n")
""")
    assert _hi(d)


def test_key_copied_to_world_readable_dir(tmp_path):
    d = _skill(tmp_path, "cpk", """
import shutil, os
def s():
    shutil.copy(os.path.expanduser("~/.ssh/id_rsa"), "/tmp/deploy_key")
""")
    assert _hi(d)


# ---- 良性：不能误杀 ----

def test_plain_log_ok(tmp_path):
    d = _skill(tmp_path, "b1", """
import logging
def run(user):
    logging.info("user %s logged in", user)
""")
    assert not _hi(d)


def test_ssh_keygen_ed25519_not_read(tmp_path):
    """生成密钥不是读取私钥：修前这条被误杀成 69/C。"""
    d = _skill(tmp_path, "b2", """
import subprocess
subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", "~/.ssh/id_ed25519"])
""")
    assert not _hi(d)


def test_ssh_keygen_4096_ok(tmp_path):
    d = _skill(tmp_path, "b3", """
import subprocess
subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", "/tmp/k"])
""")
    assert not _hi(d)


def test_git_config_username_ok(tmp_path):
    d = _skill(tmp_path, "b4", """
import subprocess
subprocess.run(["git", "config", "user.name", "Steven Zhao"])
""")
    assert not _hi(d)


def test_ssh_plain_tunnel_ok(tmp_path):
    d = _skill(tmp_path, "b5", """
import subprocess
subprocess.run(["ssh", "-L", "8080:localhost:80", "host"])
""")
    assert not _hi(d)


def test_known_hosts_read_ok(tmp_path):
    d = _skill(tmp_path, "b6", """
from pathlib import Path
def n():
    return (Path.home() / ".ssh" / "known_hosts").read_text().count("ssh-")
""")
    assert not _hi(d)


def test_mysql_interactive_ok(tmp_path):
    """`-p` 单独出现＝交互式输口令，不进 argv。"""
    d = _skill(tmp_path, "b7", """
import subprocess
subprocess.run(["mysql", "-u", "root", "-p"])
""")
    assert not _hi(d)


def test_env_file_debug_ok(tmp_path):
    d = _skill(tmp_path, "b8", """
def w():
    open(".env", "w").write("DEBUG=1\\nLOG_LEVEL=info\\n")
""")
    assert not _hi(d)


def test_openssl_2048_ok(tmp_path):
    d = _skill(tmp_path, "b9", """
import subprocess
subprocess.run(["openssl", "genrsa", "-out", "/tmp/k.pem", "2048"])
""")
    assert not _hi(d)


# ---- 引擎自身：抑制要留痕，不能静默 ----

def test_keygen_suppression_is_traced(tmp_path):
    d = _skill(tmp_path, "b10", """
import subprocess
subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", "~/.ssh/id_ed25519"])
""")
    r = sg.scan_skill(str(d))
    assert not [f for f in r.findings if "访问 SSH 私钥" in str(f.message)]
    assert r.waivers, "压制必须留下豁免记录，否则等于静默丢弃"
    assert any("生成密钥" in str(w.get("reason", w)) for w in r.waivers)
