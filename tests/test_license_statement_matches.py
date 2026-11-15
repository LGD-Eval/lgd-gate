"""README 声明的许可证，必须和 LICENSE 首行是同一族。

这是"说法与文件对上"的守卫，不是许可证选择器——选哪个协议是作者的决定，
审计能保证的只有一件事：README 说自己是什么，就不能和 LICENSE 说的不一样。

skill-audit 的历史：README 91 行里一次都没提许可证，而 LICENSE 是 Apache-2.0。
外部人看 README 不知道这仓能不能商用、能不能改——这种"没说"比"说错"更难被发现，
因为没有任何一行文字是错的。
"""
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.dirname(HERE)
SIBLINGS = ["LGD-Eval", "skill-audit", "evaluation-evidence", "evaluation-protocol"]

FAMILY = [("MIT License", "MIT"), ("Apache License", "Apache-2.0"),
          ("Attribution 4.0 International", "CC-BY-4.0"),
          ("GNU GENERAL PUBLIC", "GPL")]


def license_family(path):
    t = open(path, encoding="utf-8", errors="replace").read()[:300].lower()
    for needle, name in FAMILY:
        if needle.lower() in t:
            return name
    return "UNKNOWN"


def readme_claims(text):
    """只在许可证语境行里找协议名。

    反面教训：一开始全文搜 "MIT"，被 `commit-sha` 里的 "mit" 命中，
    把"没声明"读成"声明了 MIT"。语境行 = 含 licen / 许可 / © 的行。
    """
    hits = set()
    for line in text.splitlines():
        low = line.lower()
        if not any(k in low for k in ("licen", "许可", "©")):
            continue
        for pat, name in [(r"\bMIT\b", "MIT"), (r"\bApache", "Apache-2.0"),
                          (r"CC[- ]BY[- ]?4\.0", "CC-BY-4.0")]:
            if re.search(pat, line):
                hits.add(name)
    return hits


def test_readme_matcher_is_not_fooled_by_the_word_commit():
    """反面用例：commit-sha 里的 mit 不能被读成 MIT 许可证。"""
    assert readme_claims("徽章绑定 commit SHA\n每次新 commit CI 重扫") == set()


def _targets():
    out = [HERE] if os.path.exists(os.path.join(HERE, "LICENSE")) else []
    for s in SIBLINGS:
        d = os.path.join(WORK, s)
        if os.path.isdir(os.path.join(d, ".git")):
            out.append(d)
    return out


def test_readme_states_the_license_it_actually_ships():
    bad = []
    for d in _targets():
        lic = os.path.join(d, "LICENSE")
        rd = os.path.join(d, "README.md")
        if not (os.path.exists(lic) and os.path.exists(rd)):
            continue
        fam = license_family(lic)
        claims = readme_claims(open(rd, encoding="utf-8", errors="replace").read())
        if fam == "UNKNOWN":
            bad.append("%s: LICENSE 认不出协议族" % os.path.basename(d))
            continue
        if fam not in claims:
            bad.append("%s: LICENSE 是 %s，README 里没有一句对上（README 提到：%s）"
                       % (os.path.basename(d), fam, ",".join(sorted(claims)) or "无"))
    assert not bad, "README 与 LICENSE 对不上：\n" + "\n".join(bad)
