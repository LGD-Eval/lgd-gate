"""评估器副本的来源与同步校验。

存在原因：这个仓里的 evaluate.py 曾是**第三份独立实现**（79,256 B），
比正典少 JS 组合规则，把跨文件凭证外泄样本判成 73/B —— 而 Marketplace
上的 Action 跑的就是这一份，等于对外发布的门禁比仓库里的弱。

现在它是正典的逐字节副本，用固定哈希钉住：任何修改都必须是有意识的
同步动作（先改 LGD-Eval/skills/lgd-eval/scripts/evaluate.py，再复制过来、
更新这里的 PIN），不允许再悄悄分叉。
"""
import hashlib
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CANONICAL_SOURCE = "LGD-Eval/skills/lgd-eval/scripts/evaluate.py"
PINNED_SHA256 = "b07bb2c2666e27da7169fdc526b3bf68b8b238ed5202356ccf6f015074d513ed"


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def test_evaluate_py_is_byte_identical_to_canonical():
    actual = _sha256(os.path.join(HERE, "evaluate.py"))
    assert actual == PINNED_SHA256, (
        "evaluate.py 与正典副本不一致。\n"
        "  期望 sha256: %s\n  实际 sha256: %s\n"
        "修复方式：先改 %s，再整文件复制到本仓并更新 PINNED_SHA256；"
        "不要在本仓单独改这一份。"
        % (PINNED_SHA256, actual, CANONICAL_SOURCE)
    )


def test_evaluate_carries_js_combination_rules():
    """分叉时的具体症状：副本里没有 JS 规则，Node 技能直接满分。"""
    body = open(os.path.join(HERE, "evaluate.py"), encoding="utf-8").read()
    for needle in ("js_combination", "JS_CRED_PATH_RE", "JS_NET_SINK_RE",
                   "AUTHORIZATION_STATUS", "_sbox_env"):
        assert needle in body, "缺失 %s —— 这不是正典副本" % needle
