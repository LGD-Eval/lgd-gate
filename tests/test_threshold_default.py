"""默认门槛是消费者可见的行为，不能被人悄悄改掉。

这个测试同时守住两个方向：
  · 有人把 action.yml 的默认值调低而不写变更说明 → 失败
  · 有人让默认值与校准契约里的"当前值"记录脱节 → 失败
改默认值本身需要作者批准（A-17），批准后请同时改：
  action.yml 的 default、CALIBRATION.md 第 4 节的"current"一句、发布说明。
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _action_default():
    text = open(os.path.join(ROOT, "action.yml"), encoding="utf-8").read()
    m = re.search(r"^\s*threshold:\s*$.*?^\s*default:\s*'?(\d+)'?", text,
                  re.M | re.S)
    assert m, "action.yml 里找不到 threshold 的 default"
    return m.group(1)


def test_default_threshold_is_the_approved_value():
    """出厂默认值固定为 90，直到 A-17 获准改成 60 为止。"""
    assert _action_default() == "90", (
        "默认门槛被改动。这是消费者可见的行为变更：若已获 A-17 批准，"
        "请同时更新 CALIBRATION.md 第 4 节与发布说明，再改这里的期望值。"
    )


def test_default_is_stricter_than_the_veto_cap():
    """默认门槛必须高于封顶 49，否则"否决"在默认配置下等于没生效。"""
    assert int(_action_default()) > 49


def test_threshold_input_is_documented_as_failing_ci():
    text = open(os.path.join(ROOT, "action.yml"), encoding="utf-8").read()
    assert "CI fails below this value" in text
