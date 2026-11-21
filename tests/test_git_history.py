# -*- coding: utf-8 -*-
"""§3bz 守卫：提交历史与 .gitignore 实效力。

这一站防的是"工作区干净所以分数很高"的假安全：
密钥提交过又删掉，工作区扫描永远是满分，可每个克隆者 `git log -p` 都能拿到。
以及 `.gitignore` 的三种"看起来盖住了、其实没盖"（`!` 反向排除 / 只有注释 /
`.git/info/exclude` 没读）。
"""
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import skillgate as sg  # noqa: E402

GIT = sg.GIT_BIN()
HAS_GIT = shutil.which("git") is not None or os.path.exists(GIT)

ENV = {"GIT_AUTHOR_NAME": "g", "GIT_AUTHOR_EMAIL": "g@example.com",
       "GIT_COMMITTER_NAME": "g", "GIT_COMMITTER_EMAIL": "g@example.com"}
KEY = "sk-proj-BBBBBBBBBBBBBBBBBBBBBBBBBB"


def _git(d, *a):
    return subprocess.run([GIT, "-C", d] + list(a), capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          env=dict(os.environ, **ENV))


def _mk(tmp_path, name="r"):
    d = str(tmp_path / name)
    os.makedirs(d)
    _git(d, "init", "-q")
    _w(d, "SKILL.md", "---\nname: g\ndescription: g\n---\n")
    _commit(d, "i")
    return d


def _w(d, rel, text):
    p = os.path.join(d, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


def _commit(d, m):
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", m)


def _sev(res):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    got = [f.severity for f in res.findings if f.scoring]
    return min(got, key=lambda s: order.index(s)) if got else "NONE"


# ---------- 纯函数：.gitignore 语义 ----------

def test_last_match_wins_neutralizes_earlier_ignore():
    assert sg._gitignore_covers("*.env\n.env\n", [".env"]) is True


def test_negation_after_ignore_means_not_covered():
    # `*.env` 之后 `!*.env`：按 git 语义是"不忽略"
    assert sg._gitignore_covers("*.env\n!*.env\n", [".env"]) is False


def test_negation_before_ignore_still_covered():
    assert sg._gitignore_covers("!*.env\n*.env\n", [".env", "*.env"]) is True


def test_comment_line_is_not_coverage():
    assert sg._gitignore_covers("# .env 待补\n*.pyc\n", [".env"]) is False


def test_glob_star_prefix_forms():
    assert sg._gitignore_covers("**/.env\n", [".env"]) is True
    assert sg._gitignore_covers("/.env\n", [".env"]) is True


def test_unrelated_pattern_is_not_coverage():
    assert sg._gitignore_covers("node_modules\n*.log\n", [".env"]) is False


# ---------- 文本判据 ----------

def test_private_key_block_in_text():
    sev, what = sg._secret_hits_in_text("-----BEGIN " + "RSA PRIVATE KEY-----\nx")[0]
    assert sev == "CRITICAL" and "私钥" in what


def test_aws_secret_key_needs_real_looking_value():
    assert sg._secret_hits_in_text("aws_secret_access_key = os.environ['X']") == []
    assert sg._secret_hits_in_text("aws_secret_access_key = 'abcdefghijklmnop1234'") != []


def test_npm_token_in_text():
    assert sg._secret_hits_in_text("//registry.npmjs.org/:_authToken=abc123")[0][0] == "HIGH"


def test_public_certificate_is_not_a_secret():
    assert sg._secret_hits_in_text("-----BEGIN CERTIFICATE-----\nMIID\n") == []


# ---------- 历史扫描 ----------

@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_deleted_env_still_flagged_from_history(tmp_path):
    d = _mk(tmp_path)
    _w(d, ".env", "API_KEY=%s\n" % KEY)
    _commit(d, "add")
    os.remove(os.path.join(d, ".env"))
    _commit(d, "rm")
    res = sg.scan_skill(d)
    assert _sev(res) == "CRITICAL"


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_workspace_clean_history_dirty(tmp_path):
    d = _mk(tmp_path)
    _w(d, "config.py", "API_KEY = %r\n" % KEY)
    _commit(d, "bad")
    _w(d, "config.py", "API_KEY = os.environ['API_KEY']\n")
    _commit(d, "fix")
    res = sg.scan_skill(d)
    assert _sev(res) == "CRITICAL"
    assert any("历史" in f.message for f in res.findings)


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_secret_on_other_branch_only(tmp_path):
    """当前分支回退了，但别的分支上还留着密钥——只看 HEAD 的历史会漏。"""
    d = _mk(tmp_path)
    _w(d, ".env", "TOKEN=ghp_%s\n" % ("B" * 36))
    _commit(d, "secret")
    _git(d, "branch", "leaky")
    _w(d, "x.txt", "x\n")
    _commit(d, "x")
    _git(d, "reset", "--hard", "HEAD~2")
    res = sg.scan_skill(d)
    assert _sev(res) == "CRITICAL"


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_clean_history_not_flagged(tmp_path):
    d = _mk(tmp_path)
    _w(d, "README.md", "hi\n")
    _commit(d, "doc")
    res = sg.scan_skill(d)
    assert _sev(res) in ("NONE", "LOW", "INFO")


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_placeholder_in_history_is_benign(tmp_path):
    d = _mk(tmp_path)
    _w(d, ".env", "API_KEY=your_key_here\n")
    _commit(d, "tpl")
    os.remove(os.path.join(d, ".env"))
    _commit(d, "rm")
    res = sg.scan_skill(d)
    assert _sev(res) in ("NONE", "LOW", "INFO")


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_public_cert_in_history_is_benign(tmp_path):
    d = _mk(tmp_path)
    _w(d, "ca.crt", "-----BEGIN CERTIFICATE-----\nMIIDfake\n")
    _commit(d, "cert")
    os.remove(os.path.join(d, "ca.crt"))
    _commit(d, "rm")
    res = sg.scan_skill(d)
    assert _sev(res) in ("NONE", "LOW", "INFO")


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_negation_makes_env_unignored(tmp_path):
    d = _mk(tmp_path)
    _w(d, ".gitignore", "*.env\n!*.env\n")
    _w(d, ".env", "DEBUG=1\n")
    _commit(d, "gi")
    res = sg.scan_skill(d)
    assert _sev(res) == "HIGH"


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_info_exclude_counts_as_coverage(tmp_path):
    d = _mk(tmp_path)
    _w(d, ".git/info/exclude", ".env\n")
    _w(d, ".env", "DEBUG=1\n")
    _w(d, "README.md", "x\n")
    _commit(d, "x")
    res = sg.scan_skill(d)
    assert _sev(res) in ("NONE", "LOW", "INFO")


@pytest.mark.skipif(not HAS_GIT, reason="本机没有 git")
def test_comment_only_gitignore_is_gap(tmp_path):
    d = _mk(tmp_path)
    _w(d, ".gitignore", "# .env 待补\n")
    _w(d, ".env", "DEBUG=1\n")
    _commit(d, "gi")
    res = sg.scan_skill(d)
    assert _sev(res) == "HIGH"


def test_no_git_dir_does_not_crash(tmp_path):
    d = str(tmp_path / "plain")
    os.makedirs(d)
    _w(d, "SKILL.md", "---\nname: p\ndescription: p\n---\n")
    res = sg.scan_skill(d)
    assert _sev(res) in ("NONE", "LOW", "INFO")
