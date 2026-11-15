"""所有 evaluate_skill() 的调用方：位置解包的一个都不许留。

§3n 修了 Web 与 MCP 两处 `a,b,c,d,e = evaluate_skill(...)`，当时以为修完了。
今天外部 AI 席自己跑 `python scorecard.py .` 撞出 ValueError —— 还有第三个调用方。
类的名字不是"两个入口"，是"所有调用方"，所以这条测试自己去找调用方，不靠我记得几个。
"""
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP = {".git", "__pycache__", ".pytest_cache", "tests", "_demo", "node_modules"}

# 允许的写法：具名结果，或单值接收
OK_NAMES = {"evaluate_skill_result"}


def py_files():
    for base, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(base, f)


def test_no_positional_unpack_of_evaluate_skill():
    bad = []
    pat = re.compile(r"^\s*[A-Za-z_][\w\s,]*=\s*evaluate_skill\s*\(")
    for p in py_files():
        for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
            if not pat.search(line):
                continue
            # 单个变量接收也危险（拿到元组），但至少不会崩；多变量解包才是崩点
            lhs = line.split("=")[0]
            if lhs.count(",") >= 1:
                bad.append("%s:%d %s" % (os.path.relpath(p, HERE), i, line.strip()[:80]))
    assert not bad, ("仍在对 evaluate_skill() 做位置解包（返回值一变长就静默崩）：\n"
                     + "\n".join(bad))


def test_scorecard_imports_the_named_result():
    src = open(os.path.join(HERE, "scorecard.py"), encoding="utf-8").read()
    assert "evaluate_skill_result" in src, "scorecard.py 没有改用具名结果"
    assert "evaluate_skill(" not in src, "scorecard.py 仍在直接调用 evaluate_skill()"


def test_the_matcher_catches_the_shape_it_targets():
    """反面：把崩掉的写法喂给匹配器，必须命中。"""
    line = "    score, grade, dims, findings, warnings = evaluate_skill(os.path.abspath(path))"
    assert re.match(r"^\s*[A-Za-z_][\w\s,]*=\s*evaluate_skill\s*\(", line)
