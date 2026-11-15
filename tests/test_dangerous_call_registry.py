"""登记表守卫：把「新构造只写进一层」变成会红的测试（§3bd）。

上一站自己写下的缺口：
  "两层一致性守卫只覆盖 11 个已登记调用名，新构造只写进一层时 registry 守卫不会发现。"

实测（audit2/probe_unregistered_class.py）：12 个未登记的危险构造里 8 个 100/A+ 直通——
os.execv / os.execve / os.spawnlp / pty.spawn / runpy.run_path / ctypes.memmove 零命中。

本文件守四条：
1. 族覆盖：DANGEROUS_FAMILIES 里每个名字都必须在 CALL_SEVERITY 里登记；
2. 族不缩水：每个族的成员数不低于钉死基线（防"为了让它绿而删掉清单"）；
3. 只写一层：文本表里形如 `mod.func(` 的正则，必须能映射回 CALL_SEVERITY 里的名字；
4. 行为：以前看不见的那批构造，现在至少报一条（分数不再是 100）。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import skillgate as sg
from ast_analyzer import DangerousCallVisitor as DCV

# 族成员数基线：只许增不许减
FAMILY_BASELINE = {
    "process_replace": 8,
    "process_spawn": 14,
    "shell_wrapper": 3,
    "code_from_disk": 5,
    "deserialization": 10,
    "dynamic_import": 3,
    "native_memory": 7,
}

# 以前零命中、现在必须至少可见的构造（与探针同源）
INVISIBLE_BEFORE = {
    "os_execv": "import os\nos.execv(cmd, [cmd])\n",
    "os_execve": 'import os\nos.execve("/bin/sh", ["sh", "-c", cmd], {})\n',
    "os_spawn": "import os\nos.spawnlp(os.P_NOWAIT, cmd, cmd)\n",
    "pty_spawn": 'import pty\npty.spawn("/bin/sh")\n',
    "runpy_path": "import runpy\nrunpy.run_path(mod)\n",
    "ctypes_memmove": "import ctypes\nctypes.memmove(a, b, 8)\n",
}


def test_every_family_member_is_registered():
    missing = []
    for fam, names in DCV.DANGEROUS_FAMILIES.items():
        for n in names:
            if n not in DCV.CALL_SEVERITY:
                missing.append("%s: %s" % (fam, n))
    assert not missing, "族成员未登记进 CALL_SEVERITY（新增同类入口请一起登记）：\n" + "\n".join(missing)


def test_families_do_not_shrink():
    for fam, n in FAMILY_BASELINE.items():
        got = len(DCV.DANGEROUS_FAMILIES.get(fam, ()))
        assert got >= n, "%s 只剩 %d 个成员（基线 %d）——缩清单不等于修好" % (fam, got, n)


def test_text_table_entries_map_back_to_the_single_source():
    """文本表里每条形如 `\\bmod.func\\s*\\(` 的规则，都要能映射回 CALL_SEVERITY。

    映射不是"猜"——用 _CALL_NAME_BY_PATTERN 明确登记；这条守卫的作用是
    逼着新增文本规则的人同时回答"它在 AST 侧叫什么"，否则同一构造又会只有一层。
    """
    unmapped = []
    for row in sg.DANGEROUS_CODE_PATTERNS:
        pat = row[0]
        # 只审"点分调用名"形态的规则；其余（关键词、许可证、反例等）不在本守卫范围。
        # 注意 pattern 文本里的点通常写成 `\.`，所以正则必须允许可选的转义反斜杠——
        # 首版没允许，`\bos\.fork\s*\(` 这种就被判成"不是点分调用"整条跳过，
        # 守卫看起来是绿的、其实一条都没检查（装置自错第 14 次）。
        m = re.search(r"\\b(\w+(?:\\?\.\w+)?)\\s\*\\?\(", pat)
        if not m:
            continue
        name = m.group(1).replace("\\", "")
        if (name not in DCV.CALL_SEVERITY
                and pat not in sg._CALL_NAME_BY_PATTERN
                and pat not in sg.TEXT_ONLY_BY_DESIGN):
            unmapped.append(pat)
    assert not unmapped, "这些文本规则没有对应的 AST 调用名（只写了一层）：\n" + "\n".join(unmapped)


def test_previously_invisible_constructs_are_visible_now(tmp_path):
    """行为级守卫：分数必须离开 100，且至少有一条 finding。"""
    still_invisible = []
    for name, body in INVISIBLE_BEFORE.items():
        d = tmp_path / name
        d.mkdir()
        (d / "SKILL.md").write_text(
            "---\nname: %s\ndescription: probe %s\n---\n\n# %s\n" % (name, name, name),
            encoding="utf-8")
        (d / "main.py").write_text(body, encoding="utf-8")
        r = sg.scan_skill(str(d))
        if not r.findings or r.trust_score >= 100:
            still_invisible.append("%s score=%s findings=%d" % (name, r.trust_score, len(r.findings)))
    assert not still_invisible, "仍然看不见：\n" + "\n".join(still_invisible)


def test_literal_target_still_downgrades():
    """降噪不许被这次扩表顺手废掉：写死目标的 exec/spawn 仍应比动态低一档以上。"""
    for n in ("os.execv", "os.spawnlp"):
        dyn, lit = DCV.CALL_SEVERITY[n][:2]
        assert lit in ("LOW", "MEDIUM"), n
        assert dyn in ("CRITICAL", "HIGH", "MEDIUM"), n


def test_yaml_severity_follows_loader_not_literalness(tmp_path):
    """严重性由 Loader 决定：UnsafeLoader 必须 CRITICAL，SafeLoader / safe_load 不报。"""
    cases = {
        "unsafe": ('import yaml\nobj = yaml.load(blob, Loader=yaml.UnsafeLoader)\n', "CRITICAL"),
        "full": ('import yaml\nobj = yaml.load(blob, Loader=yaml.FullLoader)\n', "CRITICAL"),
        "safe": ('import yaml\nobj = yaml.load(blob, Loader=yaml.SafeLoader)\n', None),
        "safe_load": ('import yaml\nobj = yaml.safe_load(blob)\n', None),
    }
    bad = []
    for name, (body, want) in cases.items():
        d = tmp_path / ("yaml_" + name)
        d.mkdir()
        (d / "SKILL.md").write_text(
            "---\nname: yaml_%s\ndescription: yaml case\n---\n\n# yaml\n" % name,
            encoding="utf-8")
        (d / "main.py").write_text(body, encoding="utf-8")
        r = sg.scan_skill(str(d))
        sevs = [f.severity for f in r.findings if "yaml" in getattr(f, "message", "")]
        if want is None:
            if sevs:
                bad.append("%s 不应报 yaml，却报了 %s" % (name, sevs))
        else:
            if want not in sevs:
                bad.append("%s 应为 %s，实为 %s" % (name, want, sevs))
    assert not bad, "\n".join(bad)
