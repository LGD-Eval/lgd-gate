"""加分不能抵消扣分：基线必须是 100，不是 102。

文档写着 CRITICAL −15 / HIGH −8 / MEDIUM −4 / LOW −1，基数是 100。
实际算出来是 102——因为"零依赖 +2"加在扣分之后、clamp 之前。
后果：12 条 LOW 按文档应是 88（A，门槛 90 拦），实际算成 90（A+，门槛 90 放行）。
加分把 2 分退还给了一个有 12 个问题的技能。

实测：audit2/probe_threshold_edge.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import skillgate as sg


def score_of(low=0, med=0, high=0, crit=0):
    r = sg.ScanResult(skill_name="probe")
    # 必须有完整 frontmatter，否则会吃 −20 的"缺 frontmatter"处罚，测不到权重本身
    r.frontmatter = {"name": "probe", "description": "weights probe"}
    for sev, n in (("CRITICAL", crit), ("HIGH", high), ("MEDIUM", med), ("LOW", low)):
        for i in range(n):
            r.findings.append(sg.Finding(severity=sev, category="dangerous-code",
                                         message="probe", file="f%d.py" % i, line=1))
    return sg.compute_trust_score(r)


def test_documented_weights_add_up():
    """按文档算：100 − 12×1 = 88。"""
    assert score_of(low=12) == 88, "基数被加分抬高了（12 条 LOW 不等于 88）"
    assert score_of(low=8) == 92
    assert score_of(med=1) == 96
    assert score_of(high=1) == 69  # 仍受 HIGH 封顶约束


def test_clean_skill_still_full_marks():
    """零依赖加分不能让满分越界，但满分仍是 100。"""
    assert score_of() == 100
