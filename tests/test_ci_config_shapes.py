"""CI 配置的形状，按 GitHub 真正会读的方式验一遍——覆盖所有兄弟仓，不只本仓。

由来：`.github/FUNDING.yml` 是 GitHub 唯一会去读的资助配置位，只认键值
（github / patreon / open_collective / custom …）。四个仓把一篇 markdown 说明塞进那个位置，
YAML 解析直接失败，资助入口等于不存在；同时 `dependabot.yml` 的生态和仓库真实依赖清单没对齐
（有 package.json 却没开 npm、有 pyproject.toml 却没开 pip），自动更新只盯 Actions。

为什么不用 PyYAML：本仓没有依赖清单，为一个测试引入第三方库会把"零成本可跑"破坏掉。
这两份文件的形状都很简单，用手写解析足够，而且解析器本身也要有反面用例验证。
"""
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.dirname(HERE)
SIBLINGS = ["LGD-Eval", "skill-audit", "evaluation-evidence", "evaluation-protocol"]

FUNDING_KEYS = {
    "github", "patreon", "open_collective", "ko_fi", "tidelift", "community_bridge",
    "liberapay", "issuehunt", "lfx_crowdfunding", "polar", "buy_me_a_coffee",
    "thanks_dev", "custom",
}
DEP_FOR_MANIFEST = {"package.json": "npm", "pyproject.toml": "pip", "requirements.txt": "pip"}


def parse_funding(text):
    """返回 (keys, problems)。只允许 `key: value` 行和注释/空行。"""
    keys, problems = set(), []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^([a-z_]+)\s*:\s*(.+)$", s)
        if not m:
            problems.append("line %d 不是 key: value → %r" % (i, s[:40]))
            continue
        if m.group(1) not in FUNDING_KEYS:
            problems.append("line %d 未知键 %r" % (i, m.group(1)))
            continue
        keys.add(m.group(1))
    return keys, problems


def parse_dependabot_ecosystems(text):
    return set(re.findall(r'package-ecosystem\s*:\s*"([^"]+)"', text))


def _read(path):
    return open(path, encoding="utf-8").read()


def test_funding_parser_rejects_a_markdown_doc():
    """反面用例：把 markdown 说明放进 FUNDING.yml，必须被判成问题而不是"通过"。"""
    bad = "# Funding\n\n> LGD-Eval ｜ 支持独立评测\n\n## 资助方式\n\n- **GitHub Sponsors**\n"
    keys, problems = parse_funding(bad)
    assert problems, "markdown 说明被当成合法 FUNDING.yml 放过了"
    assert keys == set()


def test_funding_parser_accepts_the_real_shape():
    keys, problems = parse_funding("github: LGD-Eval\n")
    assert keys == {"github"} and problems == []


def _targets():
    out = [HERE] if os.path.exists(os.path.join(HERE, ".github", "FUNDING.yml")) else []
    for s in SIBLINGS:
        d = os.path.join(WORK, s)
        if os.path.isdir(os.path.join(d, ".git")):
            out.append(d)
    return out


def test_funding_yml_is_yaml_everywhere():
    bad = []
    for d in _targets():
        p = os.path.join(d, ".github", "FUNDING.yml")
        if not os.path.exists(p):
            bad.append("%s: 缺 .github/FUNDING.yml" % os.path.basename(d))
            continue
        keys, problems = parse_funding(_read(p))
        if problems or not keys:
            bad.append("%s: %s" % (os.path.basename(d), (problems or ["没有任何有效键"])[0]))
    assert not bad, "FUNDING.yml 不是 GitHub 能读的形状：\n" + "\n".join(bad)


def test_dependabot_covers_the_manifests_that_exist():
    bad = []
    for d in _targets():
        dep = os.path.join(d, ".github", "dependabot.yml")
        if not os.path.exists(dep):
            continue
        eco = parse_dependabot_ecosystems(_read(dep))
        have = {eco_name for f, eco_name in DEP_FOR_MANIFEST.items()
                if os.path.exists(os.path.join(d, f))}
        missing = sorted(have - eco)
        if missing:
            bad.append("%s: 有 %s 清单却没开 %s 生态" % (os.path.basename(d), ",".join(missing),
                                                    ",".join(missing)))
    assert not bad, "dependabot 生态缺口：\n" + "\n".join(bad)
