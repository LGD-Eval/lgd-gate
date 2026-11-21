"""隐形字符「类」覆盖守卫。

背景（灭类不灭例）：`INVISIBLE_RANGES` 声明了 14 段，但此前只实测过第一段
（U+E0000–U+E007F），就宣布这一类已覆盖。表里写着的段，没有任何东西证明它会报。

这里做三件事，缺一即红：
  1. 清单钉死：段数、每段的 (lo, hi, min_count) 与下面 EXPECTED 逐项一致
     —— 期望值写在**测试里**，不从被测表读。否则删掉一段，测试跟着少遍历一段，照样绿。
  2. 边界全覆盖：每段的 lo / hi / 中点必须报；lo-1 / hi+1 不得被本段吃掉。
  3. 阈值语义：min_count-1 次不报、min_count 次报（软连字符这类正常排版不该误杀）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import skillgate as sg

# 独立清单：改 skillgate.py 的 INVISIBLE_RANGES 必须同时改这里。
EXPECTED = {
    (0xE0000, 0xE007F): 1,
    (0x200B, 0x200F): 1,
    (0x2060, 0x2064): 1,
    (0x061C, 0x061C): 1,
    (0x202A, 0x202E): 1,
    (0x2066, 0x2069): 1,
    (0xFEFF, 0xFEFF): 1,
    (0x1D173, 0x1D17A): 1,
    (0xE0100, 0xE01EF): 1,
    (0x00AD, 0x00AD): 2,
    (0x180E, 0x180E): 2,
    (0x2800, 0x2800): 2,
    (0x3164, 0x3164): 2,
    (0xFFA0, 0xFFA0): 2,
}


def _reports(text):
    return [h[1] for h in sg.invisible_payloads(text)]


def test_manifest_matches_pinned_inventory():
    got = {(lo, hi): n for lo, hi, _l, n in sg.INVISIBLE_RANGES}
    assert len(got) == len(EXPECTED), (
        "声明 %d 段，钉死 %d 段 —— 增删区间必须同步改本测试" % (len(got), len(EXPECTED)))
    for k, n in EXPECTED.items():
        assert k in got, "缺少区间 %s–%s" % (hex(k[0]), hex(k[1]))
        assert got[k] == n, "%s–%s 的 min_count 是 %d，应为 %d" % (hex(k[0]), hex(k[1]), got[k], n)


def test_every_range_detects_its_bounds():
    """每一段的上下界都必须报 —— 不是只测第一段。"""
    bad = []
    for lo, hi, label, min_n in sg.INVISIBLE_RANGES:
        for cp in (lo, hi, (lo + hi) // 2):
            if label not in _reports("A" + chr(cp) * max(1, min_n) + "B"):
                bad.append("%s 的 %s 未报" % (label, hex(cp)))
    assert not bad, "；".join(bad)


def test_no_range_swallows_its_neighbours():
    """边界外一格不得被本段吃掉（否则是张冠李戴，会给出错误的字符名）。"""
    bad = []
    for lo, hi, label, min_n in sg.INVISIBLE_RANGES:
        for cp in (lo - 1, hi + 1):
            if cp < 0 or cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
                continue
            if label in _reports("A" + chr(cp) * max(1, min_n) + "B"):
                bad.append("%s 吃进了界外的 %s" % (label, hex(cp)))
    assert not bad, "；".join(bad)


def test_min_count_means_min_count():
    """阈值两侧都要验：差一个不报、够了就报。"""
    bad = []
    for lo, _hi, label, min_n in sg.INVISIBLE_RANGES:
        if min_n <= 1:
            continue
        if label in _reports("A" + chr(lo) * (min_n - 1) + "B"):
            bad.append("%s 在 %d 次时就报了（阈值 %d）" % (label, min_n - 1, min_n))
        if label not in _reports("A" + chr(lo) * min_n + "B"):
            bad.append("%s 在 %d 次时没报（阈值 %d）" % (label, min_n, min_n))
    assert not bad, "；".join(bad)


def test_ranges_do_not_overlap():
    """重叠会让 break 把后一段永远吃掉，后一段形同不存在。"""
    prev_hi = -1
    for lo, hi, label, _n in sorted(sg.INVISIBLE_RANGES):
        assert lo > prev_hi, "区间重叠：%s 起于 %s，上一段止于 %s" % (label, hex(lo), hex(prev_hi))
        prev_hi = hi


def test_all_file_kinds_are_scanned(tmp_path):
    """同一份注入内容放 10 种文件名/位置，逐个都必须报（不因扩展名或目录被跳过）。"""
    payload = "A" + chr(0xE0041) * 3 + "B\n"
    names = ["SKILL.md", "README.md", "notes.txt", "config.json", "a.py", "app.js",
             "x.yaml", "sub/hidden.md", "LICENSE", "noext"]
    missed = []
    for nm in names:
        p = tmp_path / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(payload, encoding="utf-8")
        res = sg.ScanResult()
        sg.scan_invisible_file(p, res)
        if not res.findings:
            missed.append(nm)
    assert not missed, "这些文件类型/位置被跳过：" + ", ".join(missed)
