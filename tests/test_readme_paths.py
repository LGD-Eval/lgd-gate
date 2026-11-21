"""README 命令里引用的路径，必须在仓库里真的存在。

由来：`python3 lgd-gate-main/evaluate.py lgd-gate-main/_demo/mitiga-style` 这条命令
把**压缩包解压目录名**写进了路径里，在仓库内直接跑 exit 2。它躲过了所有测试——
因为没有任何测试去读 README。

探针本身也错过三次，一并记在这里，因为三次都是同一个毛病"例子通过、类没通过"：
  1. 把 `65/100`、`20/25` 这类分数当路径；
  2. 把 README 里示例输出中的文件名（setup.sh、collect.py）当命令里的路径；
  3. 把占位符 `./my-skill`（文档明确说"换成你的目录"）当缺失文件。
"""
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCK = re.compile(r"```([a-zA-Z0-9]*)\r?\n(.*?)```", re.S)
CMD_LINE = re.compile(r"^(python3?|pip3?|curl|git|npx|npm|pytest|\$|\./|bash|sh|lgd|docker)\b")
TOKEN = re.compile(r"[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+|[A-Za-z0-9_.\-]+\.(?:py|md|json|yml|yaml|txt|csv)")
EXCLUDE = re.compile(r"^\d+/\d+$|^https?:|^www\.|\.github/|^[A-Za-z]:|node_modules/|^\d")
PLACEHOLDER = re.compile(r"^(\./)?my-skill/?$|^skill(s)?/?$|^your-skill/?$")


def _parse(line):
    line = re.sub(r"https?://\S+", " ", line)
    out = []
    for tok in TOKEN.findall(line):
        if EXCLUDE.search(tok) or "<" in tok or PLACEHOLDER.match(tok):
            continue
        if "/" not in tok:
            continue
        out.append(tok)
    return out


def _referenced_paths():
    text = open(os.path.join(HERE, "README.md"), encoding="utf-8").read()
    out = []
    for m in BLOCK.finditer(text):
        for raw in m.group(2).splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or not CMD_LINE.match(line):
                continue
            line = re.sub(r"https?://\S+", " ", line)
            for tok in TOKEN.findall(line):
                if EXCLUDE.search(tok) or "<" in tok or PLACEHOLDER.match(tok):
                    continue
                if "/" not in tok:
                    continue
                out.append((tok, line[:70]))
    return out


def test_readme_commands_reference_paths_that_exist():
    missing = [(tok, line) for tok, line in _referenced_paths()
               if not os.path.exists(os.path.join(HERE, tok))]
    assert not missing, "README 命令里的路径在仓库里不存在：%r" % (missing,)


def test_the_probe_actually_sees_something():
    # 反面：探针若什么都抓不到，上面那条会"静默通过"——这才是最坏的情况。
    # 所以除了真 README，还用一条合成的命令行，确定性能抓出路径来。
    assert _parse("python3 evaluate.py _demo/mitiga-style") == ["_demo/mitiga-style"]
    assert _parse("python3 lgd-gate-main/evaluate.py x") == ["lgd-gate-main/evaluate.py"]
    assert _parse("LGD Trust Score: 65/100") == []          # 分数不是路径
    assert _parse("npx lgd-eval ./my-skill") == []           # 占位符不算缺失
    assert len(_referenced_paths()) >= 1, "真 README 里一个命令路径都没抓到"
