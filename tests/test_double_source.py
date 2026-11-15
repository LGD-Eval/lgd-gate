"""同一个判断有几处实现——把"类"钉成测试，不再等下一个例子。

由来（已第六次）：等级刻度在 skillgate 与 evaluate 各有一份、规则表在两边各有一份、
引擎文件有副本、CLI 与库各算一遍、Web 与 MCP 各解包一次、CI 脚本有两个版本。
每次都是先撞见例子才去修。这个文件把剩下能枚举到的两处钉住：

  1. 两个引擎的等级刻度：0–100 每一个分数，字母必须相同（不是"边界巧合相同"，是逐点相同）。
  2. CI 门槛：evaluate.DEFAULT_THRESHOLD、lgd_audit 的退出码门槛、action.yml 的默认值，三者必须相等。
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, filename):
    path = os.path.join(HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # skillgate 内部会 import 兄弟模块，必须先注册
    spec.loader.exec_module(mod)
    return mod


def test_two_engines_agree_on_every_score():
    sg = _load("skillgate", "skillgate.py")
    ev = _load("evaluate", "evaluate.py")
    diff = []
    for score in range(0, 101):
        a = sg.grade_from_score(score)
        b = ev.grade_for(score)[0]
        if a != b:
            diff.append((score, a, b))
    assert not diff, "两个引擎在 %d 个分数上给出不同等级（分数, skillgate, evaluate）：%r" % (
        len(diff), diff[:6])


def _action_default():
    txt = open(os.path.join(HERE, "action.yml"), encoding="utf-8").read()
    m = re.search(r"threshold:.*?default:\s*'([0-9]+)'", txt, re.S)
    assert m, "action.yml 里找不到 threshold 的默认值"
    return int(m.group(1))


def test_threshold_has_one_source():
    ev = _load("evaluate", "evaluate.py")
    audit = _load("lgd_audit", "lgd_audit.py")
    yml = _action_default()
    assert ev.DEFAULT_THRESHOLD == yml, (
        "action.yml 默认门槛 %d，evaluate.DEFAULT_THRESHOLD %d —— 同一个门槛两个数"
        % (yml, ev.DEFAULT_THRESHOLD))
    assert audit._ci_threshold() == yml, (
        "lgd_audit 退出码用的门槛 %d 与 CI 默认 %d 不同 —— 本地放行、CI 拦截"
        % (audit._ci_threshold(), yml))


def test_audit_no_longer_hardcodes_ninety():
    """字面量 90 不许再出现在退出码里（豁免只给规则定义行与夹具，不给门槛）。"""
    src = open(os.path.join(HERE, "lgd_audit.py"), encoding="utf-8").read()
    assert "score >= 90" not in src, "lgd_audit 又把门槛写死了；应走 _ci_threshold()"


def test_grade_ladder_exists_in_one_function_only():
    """刻度只许有一份实现，其余模块必须委托。

    此前在 13 个边界点上验过"四份刻度一致"，但一致不等于同源——
    改一次刻度、另外三份不动，Web/MCP 会继续发旧字母，而没有任何测试会红。
    所以这里不比数值，比"谁拥有刻度"。
    """
    owners = []
    for fn in ("evaluate.py", "skillgate.py", "lgd_web.py", "eval_mcp.py", "lgd_mcp_server.py"):
        src = open(os.path.join(HERE, fn), encoding="utf-8").read()
        if "if s >= 90:" in src or "if score >= 90:" in src:
            owners.append(fn)
    # 允许两个持有者：evaluate 是评测器的刻度，skillgate 是单文件分发、不能反向依赖评测器。
    # 其余（Web / MCP / 直属脚本）必须委托，否则就是第三、第四份。
    assert set(owners) <= {"evaluate.py", "skillgate.py"}, (
        "等级阶梯被不该持有的模块实现：%r" % [x for x in owners
                                            if x not in ("evaluate.py", "skillgate.py")])
    for fn in ("lgd_web.py", "eval_mcp.py"):
        src = open(os.path.join(HERE, fn), encoding="utf-8").read()
        assert "grade_for" in src, "%s 没有委托 evaluate.grade_for" % fn

