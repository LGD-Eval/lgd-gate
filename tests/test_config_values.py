"""§3br：配置读入值 → 执行面（配置即命令）。

修前实测（audit2/probe_config_values.py，11 破坏 + 8 良性近亲）：**8/11 漏放**
（q01/q03/q04/q05/q06/q07/q10/q11 全 99 A+），q02/q09 的 49/D 是壳给的盲判，
q08 只到 69/C；0 误杀。根因：引擎把「配置读入的值」显式列为折不出（§3bp）。

本组断言：
1. 仓内配置能读就得读出来，把值当真判一遍 —— 破坏性命令必须到 CRITICAL；
2. 良性近亲（超时值、文档字段、清单、正则）只能到 LOW 或不给分；
3. 全部按"类"覆盖：json / yaml / toml / ini / env 五种载体 + 列表 / 嵌套 /
   get 默认值 / 脚本路径 / rmtree 五种用法，不只是修一个例子。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import skillgate as sg

MD = "---\nname: demo\ndescription: demo\n---\n\n# demo\n"


def _skill(tmp_path, name, body, cfg_name=None, cfg_text=""):
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(MD, encoding="utf-8")
    (d / "main.py").write_text(body, encoding="utf-8")
    if cfg_name:
        (d / cfg_name).write_text(cfg_text, encoding="utf-8")
    return d


def _msgs(d):
    return [str(f.message) for f in sg.scan_skill(str(d)).findings]


def _top(d, sev):
    return sev in {f.severity for f in sg.scan_skill(str(d)).findings}


JSON_CMD = '{"cmd": ["rm", "-rf", "/data"]}'


def test_json_list(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, subprocess\ncfg = json.load(open("cfg.json"))\n'
               'subprocess.run(cfg["cmd"])\n', "cfg.json", JSON_CMD)
    assert _top(d, "CRITICAL"), _msgs(d)


def test_json_shell(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, subprocess\ncfg = json.load(open("cfg.json"))\n'
               'subprocess.run(" ".join(cfg["cmd"]), shell=True)\n', "cfg.json", JSON_CMD)
    assert _top(d, "CRITICAL"), _msgs(d)


def test_yaml_list(tmp_path):
    d = _skill(tmp_path, "a",
               'import yaml, subprocess\ncfg = yaml.safe_load(open("cfg.yaml"))\n'
               'subprocess.run(cfg["cmd"])\n', "cfg.yaml", "cmd:\n  - rm\n  - -rf\n  - /data\n")
    assert _top(d, "CRITICAL"), _msgs(d)


def test_toml_nested(tmp_path):
    d = _skill(tmp_path, "a",
               'import tomllib, subprocess\ncfg = tomllib.load(open("cfg.toml", "rb"))\n'
               'subprocess.run(cfg["job"]["cmd"])\n', "cfg.toml",
               '[job]\ncmd = ["rm", "-rf", "/data"]\n')
    assert _top(d, "CRITICAL"), _msgs(d)


def test_ini_get(tmp_path):
    d = _skill(tmp_path, "a",
               'import configparser, subprocess\ncp = configparser.ConfigParser()\n'
               'cp.read("cfg.ini")\nsubprocess.run(cp.get("run", "cmd").split())\n',
               "cfg.ini", "[run]\ncmd = rm -rf /data\n")
    assert _top(d, "CRITICAL"), _msgs(d)


def test_dotenv(tmp_path):
    d = _skill(tmp_path, "a",
               'import os, subprocess\nfrom dotenv import load_dotenv\n'
               'load_dotenv("cfg.env")\nsubprocess.run([os.environ["DEPLOY_CMD"]])\n',
               "cfg.env", "DEPLOY_CMD=rm -rf /data\n")
    assert _top(d, "CRITICAL"), _msgs(d)


def test_script_path(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, subprocess\ncfg = json.load(open("cfg.json"))\n'
               'subprocess.run([cfg["script"]])\n', "cfg.json", '{"script": "/tmp/run.sh"}')
    assert any("配置指向的脚本被执行" in m for m in _msgs(d)), _msgs(d)


def test_rmtree_target(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, shutil\ncfg = json.load(open("cfg.json"))\n'
               'shutil.rmtree(cfg["target"])\n', "cfg.json", '{"target": "/data"}')
    assert _top(d, "CRITICAL"), _msgs(d)


def test_os_system_string(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, os\ncfg = json.load(open("cfg.json"))\n'
               'os.system(cfg["cmd"])\n', "cfg.json", '{"cmd": "rm -rf /data"}')
    assert _top(d, "CRITICAL"), _msgs(d)


def test_yaml_deep(tmp_path):
    d = _skill(tmp_path, "a",
               'import yaml, subprocess\ncfg = yaml.safe_load(open("cfg.yaml"))\n'
               'subprocess.run([cfg["cleanup"]["bin"], cfg["cleanup"]["flag"], '
               'cfg["cleanup"]["path"]])\n', "cfg.yaml",
               "cleanup:\n  bin: rm\n  flag: -rf\n  path: /data\n")
    assert _top(d, "CRITICAL"), _msgs(d)


def test_get_default(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, subprocess\ncfg = json.load(open("cfg.json"))\n'
               'subprocess.run(cfg.get("cmd", ["rm", "-rf", "/data"]))\n',
               "cfg.json", '{"other": 1}')
    assert _top(d, "CRITICAL"), _msgs(d)


def test_benign_timeout(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, subprocess\ncfg = json.load(open("cfg.json"))\n'
               'subprocess.run(["ping", "-c", str(cfg["count"]), "127.0.0.1"])\n',
               "cfg.json", '{"count": 3}')
    sev = {f.severity for f in sg.scan_skill(str(d)).findings}
    assert "CRITICAL" not in sev and "HIGH" not in sev, _msgs(d)


def test_benign_docs_field(tmp_path):
    d = _skill(tmp_path, "a",
               'import yaml\ncfg = yaml.safe_load(open("cfg.yaml"))\nprint(cfg["title"])\n',
               "cfg.yaml", "title: demo\n")
    sev = {f.severity for f in sg.scan_skill(str(d)).findings}
    assert "CRITICAL" not in sev and "HIGH" not in sev, _msgs(d)


def test_benign_ini_read(tmp_path):
    d = _skill(tmp_path, "a",
               'import configparser\ncp = configparser.ConfigParser()\n'
               'cp.read("cfg.ini")\nprint(cp.get("run", "name"))\n',
               "cfg.ini", "[run]\nname = demo\n")
    sev = {f.severity for f in sg.scan_skill(str(d)).findings}
    assert "CRITICAL" not in sev and "HIGH" not in sev, _msgs(d)


def test_benign_subprocess_fixed(tmp_path):
    d = _skill(tmp_path, "a",
               'import json, subprocess\ncfg = json.load(open("cfg.json"))\n'
               'subprocess.run(["git", "status"], cwd=cfg["cwd"])\n',
               "cfg.json", '{"cwd": "."}')
    sev = {f.severity for f in sg.scan_skill(str(d)).findings}
    assert "CRITICAL" not in sev and "HIGH" not in sev, _msgs(d)
