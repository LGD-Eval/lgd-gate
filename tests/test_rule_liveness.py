"""规则表活性守卫：每一条正则都必须有一条「会响」的见证输入。

为什么需要：`PROMPT_INJECTION_PATTERNS`(27) / `REMOTE_EXEC_PATTERNS`(11) /
`HONESTY_PATTERNS`(2) / `DANGEROUS_CODE_PATTERNS`(34) / `INSTALL_HOOKS`(7) 都只是"声明"。
声明得再漂亮，如果正则永远匹配不到任何东西，它在线上就是一行死代码——
表里有、报告里没有，谁都发现不了。

做法：`tools/rule_witness.py` 按 token 展开正则，生成一条应当被它匹配的样例，
再验证 `re.search` 成立。不成立 ⇒ 这条规则要么写错了，要么永远不响。
（能自证 ≠ 覆盖够；覆盖问题由别的测试与本仓 corpus 负责。）

已知局限（写在这里免得下次又当成洞）：取样器处理不了非常规语法时会给近似样例，
遇到自证失败先人工看一眼是不是取样器的问题——**装置也会骗人**。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import skillgate as sg
from rule_witness import sample_for

TABLES = ("PROMPT_INJECTION_PATTERNS", "REMOTE_EXEC_PATTERNS", "HONESTY_PATTERNS",
          "DANGEROUS_CODE_PATTERNS", "INSTALL_HOOKS")

# 钉死的条数：增删规则必须同步改这里，否则守卫红（防"悄悄少一条"）
EXPECTED_COUNTS = {
    "PROMPT_INJECTION_PATTERNS": 27,
    "REMOTE_EXEC_PATTERNS": 11,
    "HONESTY_PATTERNS": 2,
    "DANGEROUS_CODE_PATTERNS": 34,
    "INSTALL_HOOKS": 7,
}


def _patterns(name):
    table = getattr(sg, name)
    out = []
    for entry in table:
        out.append(entry[0] if isinstance(entry, (list, tuple)) else entry)
    return out


def test_table_sizes_are_pinned():
    for name, n in EXPECTED_COUNTS.items():
        got = len(getattr(sg, name))
        assert got == n, "%s 有 %d 条，钉死的是 %d 条 —— 增删规则请同步改本测试" % (name, got, n)


def test_every_pattern_has_a_witness():
    """每一条正则都要能被自己的见证样例匹配到。"""
    bad = []
    for name in EXPECTED_COUNTS:
        for pat in _patterns(name):
            assert isinstance(pat, str) and pat, "%s 里有空模式" % name
            try:
                rx = re.compile(pat)
            except re.error as e:
                bad.append("%s 编译失败 %r：%s" % (name, pat[:50], e))
                continue
            w = sample_for(pat)
            if not rx.search(w):
                bad.append("%s 无见证 %r（样例 %r）" % (name, pat[:50], w[:30]))
    assert not bad, "\n".join(bad[:10])


def test_no_pattern_registered_twice():
    dup = []
    for name in EXPECTED_COUNTS:
        seen = {}
        for pat in _patterns(name):
            if pat in seen:
                dup.append("%s 重复登记 %r" % (name, pat[:50]))
            seen[pat] = 1
    assert not dup, "\n".join(dup)


def test_witness_generator_is_not_trivially_permissive():
    """反向：取样器不能靠"返回空串/万能串"混过——几条已知规则必须由样本命中。"""
    cases = {
        r"eval\s*\(": "eval(",
        r"\bos\.system\s*\(": "os.system(",
        r"600\+\s+rules": "600+ rules",
    }
    for pat, want in cases.items():
        w = sample_for(pat)
        assert re.search(pat, w), "取样器对 %r 给出 %r，匹配不上" % (pat, w)
        assert w.strip(), "取样器对 %r 返回空串" % pat
