# -*- coding: utf-8 -*-
"""P1-6 语料 + 度量：生成 18 份标注样本，跑原型与既有 skillgate，算漏报/误报。"""
import ast
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORP = os.path.join(HERE, "corpus")
SKILLGATE = r"C:\Users\Administrator\AppData\Local\Temp\xlgd_audit\lgd-gate\skillgate.py"
sys.path.insert(0, HERE)
import taint_scan  # noqa

SAMPLES = {
    # ---- Python: 应检出（vuln）----
    "py_direct_exec.py": ("vuln", """
import sys
def main():
    cmd = input("cmd> ")
    exec(cmd)
main()
"""),
    "py_env_to_system.py": ("vuln", """
import os
def run():
    target = os.environ.get("TARGET")
    os.system("ping " + target)
run()
"""),
    "py_argv_subprocess.py": ("vuln", """
import sys, subprocess
def go():
    host = sys.argv[1]
    subprocess.run("ssh " + host, shell=True)
go()
"""),
    "py_dynamic_write.py": ("vuln", """
import sys
def save():
    p = sys.argv[1]
    f = open(p, "w")
    f.write("x")
save()
"""),
    "py_indirect_forwarder.py": ("vuln", """
import sys
from helper_fwd import sh
def main():
    sh(sys.argv[1])
main()
"""),
    "py_base64_exec.py": ("vuln", """
import base64
payload = base64.b64decode("cHJpbnQoMSk=")
exec(payload)
"""),
    "py_unquote_popen.py": ("vuln", """
import os, urllib.parse
v = urllib.parse.unquote("%2F%65%74%63")
os.popen("cat " + v)
"""),
    "py_tainted_rmtree.py": ("vuln", """
import os, shutil
d = os.environ["CLEAN_DIR"]
shutil.rmtree(d)
"""),

    # ---- Python: 不应检出（safe）----
    "py_const_subprocess.py": ("safe", """
import subprocess
subprocess.run(["ls", "-l"], check=True)
"""),
    "py_log_only.py": ("safe", """
import sys
name = sys.argv[1]
print("hello %s" % name)
"""),
    "py_const_exec.py": ("safe", """
exec("print('static')")
"""),
    "py_fstring_log.py": ("safe", """
import os
u = os.environ.get("USER")
print(f"user={u}")
"""),

    # ---- 转发器（neutral，单独不报）----
    "helper_fwd.py": ("neutral", """
import os
def sh(arg):
    os.system(arg)
"""),

    # ---- JS: 应检出（vuln）----
    "js_eval_req.js": ("vuln", """
router.post('/run', (req, res) => {
  const code = req.body.code;
  eval(code);
});
"""),
    "js_child_exec.js": ("vuln", """
const cp = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  cp.exec('ping ' + host);
});
"""),
    "js_dynamic_require.js": ("vuln", """
app.get('/mod', (req, res) => {
  const name = req.query.name;
  require(name);
});
"""),

    # ---- JS: 不应检出（safe）----
    "js_benign_exec.js": ("safe", """
const cp = require('child_process');
cp.execSync('ls -l');
"""),

    # ---- Shell: 应检出（vuln）----
    "sh_remote_pipe.sh": ("vuln", """
curl -s https://example.com/install.sh | sh
"""),
    "sh_rm_var.sh": ("vuln", """
rm -rf $TARGET_DIR
"""),

    # ---- Shell: 不应检出（safe）----
    "sh_benign.sh": ("safe", """
echo "hello"
ls -l /tmp
"""),
}


def main():
    os.makedirs(CORP, exist_ok=True)
    for name, (label, body) in SAMPLES.items():
        with open(os.path.join(CORP, name), "w", encoding="utf-8") as f:
            f.write(body.lstrip("\n"))
    with open(os.path.join(CORP, "labels.json"), "w", encoding="utf-8") as f:
        json.dump({k: v[0] for k, v in SAMPLES.items()}, f, indent=2, ensure_ascii=False)

    labels = {k: v[0] for k, v in SAMPLES.items()}
    # 跨文件索引：先扫一遍所有 .py，汇总"把参数送进 sink"的转发函数
    global_fwd = {}
    for name in labels:
        if name.endswith(".py"):
            try:
                tree = ast.parse(open(os.path.join(CORP, name), encoding="utf-8").read())
                global_fwd.update(taint_scan.collect_forwarders(tree))
            except Exception:
                pass

    rows = []
    for name, label in labels.items():
        p = os.path.join(CORP, name)
        try:
            found = taint_scan.scan_file(p, global_fwd)
        except Exception as e:
            found = [{"rule": "EXCEPTION", "err": repr(e)}]
        rows.append({"file": name, "label": label, "hits": len(found),
                     "rules": sorted({h.get("rule") for h in found})})

    tp = sum(1 for r in rows if r["label"] == "vuln" and r["hits"] > 0)
    fn = sum(1 for r in rows if r["label"] == "vuln" and r["hits"] == 0)
    fp = sum(1 for r in rows if r["label"] == "safe" and r["hits"] > 0)
    tn = sum(1 for r in rows if r["label"] == "safe" and r["hits"] == 0)
    neu_hit = sum(1 for r in rows if r["label"] == "neutral" and r["hits"] > 0)
    recall = tp / (tp + fn) if tp + fn else 0
    precision = tp / (tp + fp) if tp + fp else 0

    # 与既有正则扫描器对比
    sg = {}
    if os.path.exists(SKILLGATE):
        r = subprocess.run([sys.executable, SKILLGATE, "scan", CORP, "--format", "json"],
                           capture_output=True, text=True, encoding="utf-8", timeout=120)
        try:
            sg = json.loads(r.stdout)
        except Exception:
            sg = {"__raw": (r.stdout or r.stderr)[:1200]}

    result = {
        "corpus_size": len(labels),
        "confusion": {"TP": tp, "FN": fn, "FP": fp, "TN": tn, "neutral_flagged": neu_hit},
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "rows": rows,
        "skillgate_baseline": sg,
        "note": "18 份自建标注样本，非生产语料；指标仅用于证明能力方向，不等于线上漏报率。",
    }
    out = os.path.join(r"C:\Users\Administrator\Doubao\chats\2026-11-19\new-chat-6\XLGD整改审计_20261119\evidence",
                       "p10_taint_metrics.json")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, ensure_ascii=False, indent=2)[:3500])
    print("\nROWS:")
    for r in rows:
        print("  %-28s %-8s hits=%d %s" % (r["file"], r["label"], r["hits"], r["rules"]))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
