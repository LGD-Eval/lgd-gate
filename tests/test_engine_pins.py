"""引擎文件的指纹钉子：改一份、忘了同步另外两份，立刻红。

为什么需要这条：§3i/§3j 那次"分叉"最后一查，是**我自己**的错——我改了 gate 的
`skillgate.py`（120,641 B），LGD-Eval 还停在已发布的 72,112 B，我把两份放在一起比，
然后把它写成"另一个仓缺整张表"。从外面量，公开的两个仓是同一个 blob，谁也没少。

所以真正要修的不是"某个仓缺东西"，而是**没有任何机制在我改完之后提醒我同步**。
这条测试就是那个机制，并且钉在"我实际动手的那一侧"（本仓），而不是被同步的那一侧：

  - 本仓 `skillgate.py` / `js_analyzer.py` 的 SHA-256 写在下面；
  - 改动后忘了更新 PIN → 红；
  - 同机存在 LGD-Eval 的三份副本时，逐字节比对，不一致也红；
  - 副本路径不存在时跳过那一条（CI 里只有一份树），但 PIN 那条永远生效。

三种副本（本仓 / LGD-Eval skills / LGD-Eval vendor）必须字节相同，这是 §3i 定的口径。
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

PIN = {
    "skillgate.py": "ecf17185493ad234",
    "js_analyzer.py": "97bce99b6ba580aa",
}

# 同机另两份副本（相对本仓的兄弟目录）。CI 上不存在就跳过比对，但 PIN 不跳过。
PEERS = [
    os.path.join(os.path.dirname(HERE), "LGD-Eval", "skills", "lgd-eval", "scripts"),
    os.path.join(os.path.dirname(HERE), "LGD-Eval", "vendor", "scripts"),
    os.path.join(os.path.dirname(HERE), "LGD-Eval", "skills", "lgd-eval", "scripts"),
]


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def test_engine_files_match_their_pins():
    for name, pin in PIN.items():
        actual = _sha(os.path.join(HERE, name))[:16]
        assert actual == pin, (
            "%s 的指纹变了（%s → %s）。改引擎必须：同步三份副本 → 更新本文件 PIN "
            "→ 更新 LGD-Eval 的 provenance PIN。不做这三步，两个仓就会在我不知道的时候分叉。"
            % (name, pin, actual))


def test_sibling_copies_are_byte_identical_when_present():
    checked = []
    for d in PEERS:
        for name in PIN:
            p = os.path.join(d, name)
            if not os.path.exists(p):
                continue
            assert _sha(p) == _sha(os.path.join(HERE, name)), (
                "%s 与 %s 不一致——三份副本必须字节相同" % (p, name))
            checked.append(p)
    # 反面：一个副本都没比对到时，说明路径写错了，而不是"不需要比"
    if os.path.isdir(os.path.join(os.path.dirname(HERE), "LGD-Eval")):
        assert checked, "LGD-Eval 在，却一份副本都没比对到——PEERS 路径可能写错"
