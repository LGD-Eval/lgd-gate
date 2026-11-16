# -*- coding: utf-8 -*-
"""§3by 守卫：敏感文件与机密清单（secret files on disk）。

对应 audit2/probe_secret_files.py 的 12 攻击 / 8 良性。
纪律「灭类不灭例」：每条判据都要有"类"的样例，而不只是复现探针里那一个例。
"""
import io
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import skillgate as sg  # noqa: E402

PK = ("-----BEGIN " + "RSA PRIVATE KEY-----\n"
      "MIIEowIBAAKCAQEA7fakefakefakefakefakefakefakefakefake\n"
      "-----END RSA PRIVATE KEY-----\n")
PK_OPENSSH = ("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
              "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
              "-----END " + "OPENSSH PRIVATE KEY-----\n")
CERT = ("-----BEGIN CERTIFICATE-----\n"
        "MIIDdzCCAl+gAwIBAgIEfakefakefakefakefakefakefakefake\n"
        "-----END CERTIFICATE-----\n")
MD = "---\nname: fixture\ndescription: fixture\n---\n\n# fixture\n"


def make(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        io.open(str(p), "w", encoding="utf-8").write(text)
    io.open(str(tmp_path / "SKILL.md"), "w", encoding="utf-8").write(MD)
    return sg.scan_skill(str(tmp_path))


def top(r):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sev = [f.severity for f in r.findings if f.severity in order]
    if not sev:
        return "LOW"
    return sorted(sev, key=lambda s: order[s])[0]


def msgs(r):
    return " ".join(str(f.message) for f in r.findings)


# ---------------- 攻击：私钥文件 ----------------


def test_rsa_key_file_critical(tmp_path):
    assert top(make(tmp_path, {"id_" + "rsa": PK})) == "CRITICAL"


def test_rsa_name_alone_critical(tmp_path):
    # 类：判据不能只靠内容。私钥文件经 base64 重排后没有 PEM 头，仍然是私钥文件；
    # 只有名字表能抓住它（摘掉名字表时这条必须红）。
    assert top(make(tmp_path, {"id_" + "rsa": "b3BlbnNzaC1rZXk6IG5vIGhlYWRlcgo=\n"})) == "CRITICAL"


def test_openssh_key_file_critical(tmp_path):
    assert top(make(tmp_path, {"id_" + "ed25519": PK_OPENSSH})) == "CRITICAL"


def test_pem_private_key_critical(tmp_path):
    assert top(make(tmp_path, {"deploy.pem": PK})) == "CRITICAL"


def test_ecdsa_key_name_critical(tmp_path):
    assert top(make(tmp_path, {"id_" + "ecdsa": PK})) == "CRITICAL"


def test_tilde_style_key_name_critical(tmp_path):
    # 类：不同名字、同一行为——id_dsa 也是私钥
    assert top(make(tmp_path, {"id_" + "dsa": PK})) == "CRITICAL"


def test_p12_bundle_high(tmp_path):
    assert top(make(tmp_path, {"client.p12": "MIACAQMwgAYJKoZIhvcNAQcBoIAEgZQwggSQ\n"})) == "HIGH"


def test_pfx_bundle_high(tmp_path):
    assert top(make(tmp_path, {"cert.pfx": "MIIFakebinarycontent\n"})) == "HIGH"


# ---------------- 攻击：凭证文件存在 ----------------------------


def test_git_credentials_critical(tmp_path):
    assert top(make(tmp_path, {"." + "git-credentials": "https://u:t@github.com\n"})) == "CRITICAL"


def test_aws_credentials_critical(tmp_path):
    r = make(tmp_path, {"." + "aws/credentials":
                        "[default]\naws_access_key_id=AKIA1\naws_secret_access_key=abcdefgh\n"})
    assert top(r) == "CRITICAL"


def test_gcp_service_account_critical(tmp_path):
    body = '{"type":"service_account","private_key":"%s"}\n' % PK.replace("\n", "\\n")
    assert top(make(tmp_path, {"credentials.json": body})) == "CRITICAL"


def test_npmrc_authtoken_high(tmp_path):
    r = make(tmp_path, {"." + "npmrc":
                        "//registry.npmjs.org/:_authToken=npm_abcdefghij0123456789\n"})
    assert top(r) == "HIGH"
    assert "_authToken" in msgs(r)


def test_kubeconfig_client_key_high(tmp_path):
    r = make(tmp_path, {"kubeconfig": "clusters:\n- cluster:\n    server: https://k\n"
                       "    client-key-data: TFNZQUFBQUFBQUFBQUFB\n"})
    assert top(r) == "HIGH"


def test_k8s_secret_manifest_high(tmp_path):
    r = make(tmp_path, {"secret.yaml": "apiVersion: v1\nkind: Secret\ndata:\n"
                       "  password: aHVudGVyMmh1bnRlcjI=\n"})
    assert top(r) == "HIGH"


# ---------------- 攻击：.gitignore 没盖住 ----------------------------


def test_env_with_secret_and_no_gitignore_critical(tmp_path):
    assert top(make(tmp_path, {".env": "API_KEY=sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"})) == "CRITICAL"


def test_env_without_gitignore_coverage_high(tmp_path):
    # 内容本身不敏感（DEBUG=1），但 .env 在仓库里且没被 ignore：
    # 下一次 git add -A 就进历史，而历史一旦推送收不回。
    r = make(tmp_path, {".env": "DEBUG=1\n"})
    assert top(r) == "HIGH"


def test_env_ignored_but_secret_still_critical(tmp_path):    # 盖住了也不该放行：内容级判据独立于覆盖度
    r = make(tmp_path, {".env": "TOKEN=ghp_" + "A" * 36 + "\n", ".gitignore": ".env\n"})
    assert top(r) == "CRITICAL"


def test_keyfile_not_covered_by_gitignore_noted(tmp_path):
    r = make(tmp_path, {".env": "DEBUG=1\n", ".gitignore": ".env\n",
                        "server.crt": CERT, "notes.txt": "hello\n"})
    assert top(r) == "LOW"      # 只有公开证书 → 不判
    # 私钥文件 + .gitignore 只盖 .env：文件本身已判级，覆盖缺口以豁免记录留痕
    r2 = make(tmp_path, {".env": "DEBUG=1\n", ".gitignore": ".env\n", "ca.key": PK})
    assert top(r2) == "CRITICAL"
    assert any("gitignore" in str(w.get("message", "")) for w in r2.waivers)


# ---------------- 良性 ----------------------------


def test_env_example_benign(tmp_path):
    assert top(make(tmp_path, {".env.example": "API_KEY=\nDEBUG=\n"})) == "LOW"


def test_env_only_flags_benign(tmp_path):
    assert top(make(tmp_path, {".env": "DEBUG=1\nLOG_LEVEL=info\n", ".gitignore": ".env\n"})) == "LOW"


def test_public_cert_benign(tmp_path):
    assert top(make(tmp_path, {"certs/server.crt": CERT})) == "LOW"


def test_public_cert_pem_benign(tmp_path):
    assert top(make(tmp_path, {"tests/fixtures/ca.pem": CERT})) == "LOW"


def test_gitignore_list_benign(tmp_path):
    assert top(make(tmp_path, {".gitignore": ".env\n*.pem\n*.key\nid_" + "rsa\n"})) == "LOW"


def test_readme_keygen_benign(tmp_path):
    r = make(tmp_path, {"README.md": "## 生成密钥\n\n```bash\n"
                        "ssh-keygen -t ed25519 -f ~/.ssh/id_" + "ed25519\n```\n"})
    assert top(r) == "LOW"


def test_plain_config_benign(tmp_path):
    assert top(make(tmp_path, {"config.yaml": "timeout: 30\nretries: 3\n"})) == "LOW"


def test_private_key_in_docs_critical_and_disclosed(tmp_path):
    # 文档里的私钥块**不降级**：复制即用。是否对文档语境降档是待拍板口径，
    # 本站不做自行决定，只把现状钉死，避免"哪天静默变松"没人发现。
    assert top(make(tmp_path, {"GUIDE.md": "示例：\n" + PK})) == "CRITICAL"


def test_cache_dirs_not_in_scope(tmp_path):
    # 装置自错 ㉞ 的回归守卫：缓存目录不是仓库内容
    d = tmp_path / ".pytest_cache" / "v" / "cache"
    d.mkdir(parents=True)
    io.open(str(d / "nodeids"), "w", encoding="utf-8").write("x[----BEGIN " + PK + "]\n")
    io.open(str(tmp_path / "SKILL.md"), "w", encoding="utf-8").write(MD)
    r = sg.scan_skill(str(tmp_path))
    assert top(r) == "LOW"


if __name__ == "__main__":
    raise SystemExit(pytest.main([os.path.abspath(__file__), "-q"]))
