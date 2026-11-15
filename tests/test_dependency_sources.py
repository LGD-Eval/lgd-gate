"""依赖声明的覆盖面：requirements.txt 只是其中一种写法。

修复前只读 `requirements.txt`。真实技能把依赖写在 `pyproject.toml` 里很常见，
于是"已扫依赖"在那类仓里等于"什么都没扫"——而且这类漏报不会报错，
它只会安静地少一行。
"""
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import skillgate  # noqa: E402


def _offline(monkeypatch):
    def boom(*a, **k):
        raise OSError("offline in test")
    monkeypatch.setattr(urllib.request, "urlopen", boom)


def _skill(root, files):
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# Dep Tool\n\nReads data.\n")
    for rel, body in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
    return root


def _deps_findings(skill_dir):
    return [f for f in skillgate.scan_skill(str(skill_dir)).findings
            if f.category in ("dependency-scan", "dependency-vuln")]


def test_pyproject_pep621_dependencies_are_parsed(tmp_path, monkeypatch):
    _offline(monkeypatch)
    toml = "[project]\nname = \"t\"\nversion = \"1\"\ndependencies = [\"requests==2.31.0\"]\n"
    skill = _skill(tmp_path / "s", {"pyproject.toml": toml})
    msgs = " ".join(f.message for f in _deps_findings(skill))
    assert "requests" in msgs, msgs


def test_pyproject_poetry_dependencies_are_parsed(tmp_path, monkeypatch):
    _offline(monkeypatch)
    toml = ("[tool.poetry.dependencies]\npython = \"^3.11\"\n"
            "requests = \"==2.31.0\"\n")
    skill = _skill(tmp_path / "s", {"pyproject.toml": toml})
    msgs = " ".join(f.message for f in _deps_findings(skill))
    assert "requests" in msgs and "python" not in msgs.lower().replace("python 3", ""), msgs


def test_requirements_dev_is_also_read(tmp_path, monkeypatch):
    _offline(monkeypatch)
    skill = _skill(tmp_path / "s", {"requirements-dev.txt": "flask==3.0.0\n"})
    msgs = " ".join(f.message for f in _deps_findings(skill))
    assert "flask" in msgs, msgs


def test_nested_scripts_requirements_is_also_read(tmp_path, monkeypatch):
    _offline(monkeypatch)
    skill = _skill(tmp_path / "s", {"scripts/requirements.txt": "django==4.2.0\n"})
    msgs = " ".join(f.message for f in _deps_findings(skill))
    assert "django" in msgs, msgs


def test_no_dependency_file_means_no_dependency_noise(tmp_path):
    skill = _skill(tmp_path / "s", {"scripts/run.py": "print('ok')\n"})
    assert not _deps_findings(skill), "没有依赖声明就不该冒出依赖类命中"


def test_ranged_dependency_still_says_undecidable(tmp_path):
    skill = _skill(tmp_path / "s", {"requirements.txt": "requests>=2.31,<3\n"})
    hits = _deps_findings(skill)
    assert any("无法判定" in f.message for f in hits), [f.message for f in hits]
    assert all("latest" not in f.message for f in hits)


def test_dev_dependency_range_is_informational_not_a_runtime_finding(tmp_path):
    """开发依赖不进运行时。

    实测踩到过：lgd-eval 自己的 pyproject 里有 `pytest>=7`，
    一刀切成 MEDIUM 会把自家技能从 90 扣到 86——理由不成立，属于自伤噪音。
    """
    toml = ("[project]\nname = \"t\"\nversion = \"1\"\n"
            "dependencies = [\"requests==2.31.0\"]\n"
            "[project.optional-dependencies]\ndev = [\"pytest>=7\"]\n")
    skill = _skill(tmp_path / "s", {"pyproject.toml": toml})
    hits = [f for f in _deps_findings(skill) if "开发依赖" in f.message]
    assert hits and hits[0].severity == "LOW", [(f.severity, f.message) for f in hits]
    assert not [f for f in _deps_findings(skill)
                if "无法判定" in f.message and "pytest" in f.message]


def test_package_json_dependencies_are_parsed(tmp_path, monkeypatch):
    """修复前 package.json 只查安装钩子，依赖从不进漏洞库——一个生态的整块缺口。"""
    _offline(monkeypatch)
    pkg = ('{"name":"t","version":"1.0.0",'
           '"dependencies":{"lodash":"4.17.15"},'
           '"devDependencies":{"jest":"^29.0.0"}}')
    skill = _skill(tmp_path / "s", {"package.json": pkg})
    msgs = " ".join(f.message for f in _deps_findings(skill))
    assert "lodash" in msgs, msgs
    assert any("开发依赖" in f.message and "jest" in f.message
               for f in _deps_findings(skill)), [f.message for f in _deps_findings(skill)]


def test_package_lock_resolved_version_is_what_gets_checked(tmp_path, monkeypatch):
    """声明写 ^4.17.15，锁文件写 4.17.15——查的是装到机器上的那个版本。"""
    _offline(monkeypatch)
    lock = ('{"name":"t","lockfileVersion":3,"packages":{'
            '"":{"name":"t","version":"1.0.0"},'
            '"node_modules/lodash":{"version":"4.17.15"}}}')
    skill = _skill(tmp_path / "s", {"package-lock.json": lock})
    msgs = " ".join(f.message for f in _deps_findings(skill))
    assert "lodash" in msgs, msgs


def test_package_lock_dev_flag_becomes_development_semantics(tmp_path, monkeypatch):
    _offline(monkeypatch)
    lock = ('{"lockfileVersion":3,"packages":{'
            '"node_modules/jest":{"version":"29.0.0","dev":true},'
            '"node_modules/lodash":{"version":"4.17.15"}}}')
    skill = _skill(tmp_path / "s", {"package-lock.json": lock})
    dev = [f for f in _deps_findings(skill) if "jest" in f.message]
    assert dev and "开发依赖" in dev[0].message, [f.message for f in dev]


def test_poetry_lock_packages_are_parsed(tmp_path, monkeypatch):
    _offline(monkeypatch)
    lock = '[[package]]\nname = "django"\nversion = "4.2.0"\ndescription = "x"\n'
    skill = _skill(tmp_path / "s", {"poetry.lock": lock})
    msgs = " ".join(f.message for f in _deps_findings(skill))
    assert "django" in msgs, msgs


def test_dependency_cap_is_disclosed_not_silent(tmp_path, monkeypatch):
    """超过查询上限的依赖必须被报出来。

    修复前超出的部分既不查也不说，报告上看起来像"全部扫过"。
    """
    _offline(monkeypatch)
    lines = "\n".join("pkg%02d==1.0.%d" % (i, i) for i in range(13))
    skill = _skill(tmp_path / "s", {"requirements.txt": lines + "\n"})
    cap_hits = [f for f in _deps_findings(skill) if "只查了" in f.message]
    assert cap_hits and "13" in cap_hits[0].message, \
        [f.message for f in _deps_findings(skill)]


def test_manifest_and_lock_deduped(tmp_path, monkeypatch):
    _offline(monkeypatch)
    pkg = '{"name":"t","dependencies":{"lodash":"4.17.15"}}'
    lock = '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}'
    skill = _skill(tmp_path / "s", {"package.json": pkg, "package-lock.json": lock})
    hits = [f for f in _deps_findings(skill) if "lodash" in f.message]
    assert len(hits) == 1, [f.message for f in hits]


def test_caret_range_is_undecidable_not_a_fake_version(tmp_path):
    pkg = '{"name":"t","dependencies":{"lodash":"^4.17.15"}}'
    skill = _skill(tmp_path / "s", {"package.json": pkg})
    hits = _deps_findings(skill)
    assert any("无法判定" in f.message for f in hits), [f.message for f in hits]
    assert all("latest" not in f.message and "lodash==4" not in f.message for f in hits)
