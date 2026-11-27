# -*- coding: utf-8 -*-
"""P0-1 边界/负向/正向测试：统一时效元数据。"""
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from review_status import review_meta, assert_consistent  # noqa

T = dt.date(2026, 11, 19)
CASES = []


def case(name, expect, **kw):
    CASES.append((name, expect, kw))


def d(offset):
    return (T + dt.timedelta(days=offset)).isoformat()


# 正向
case("新鲜+未到期", {"freshness": "ok", "overdue": False, "review_status": "ok",
                    "fail_closed": False, "warning": False}, as_of=d(-10), next_review=d(30))
# 边界：恰好 90 天
case("边界 90 天", {"freshness": "ok", "age_days": 90, "review_status": "ok"}, as_of=d(-90), next_review=d(10))
case("边界 91 天", {"freshness": "aging", "age_days": 91, "effective_risk": "medium"}, as_of=d(-91), next_review=d(10))
case("边界 180 天", {"freshness": "aging", "age_days": 180}, as_of=d(-180), next_review=d(10))
case("边界 181 天", {"freshness": "stale", "effective_risk": "high"}, as_of=d(-181), next_review=d(10))
# 核心缺陷复现：as_of 未超 90 天，但 next_review 已过期
case("89 天 + 复核已逾期", {"freshness": "ok", "overdue": True, "review_status": "overdue",
                        "effective_risk": "high", "warning": True}, as_of=d(-89), next_review=d(-7))
# 复核到期当日
case("复核当日到期", {"overdue": False, "review_status": "due", "warning": True}, as_of=d(-10), next_review=d(0))
# 负向：日期异常
case("as_of 缺失", {"freshness": "unknown", "review_status": "unknown",
                  "fail_closed": True, "warning": True}, as_of=None, next_review=d(10))
case("as_of 空串", {"fail_closed": True}, as_of="", next_review=d(10))
case("as_of 非法月", {"fail_closed": True}, as_of="2026-13-45", next_review=d(10))
case("as_of 2月30", {"fail_closed": True}, as_of="2026-02-30", next_review=d(10))
case("as_of 带时区", {"fail_closed": True}, as_of="2026-11-01T00:00:00+08:00", next_review=d(10))
case("as_of 未来日期", {"freshness": "invalid", "review_status": "invalid",
                     "fail_closed": True, "warning": True}, as_of=d(40), next_review=d(60))
case("next_review 缺失", {"overdue": False, "review_status": "unscheduled",
                       "fail_closed": False, "warning": True}, as_of=d(-10), next_review=None)
case("next_review 非法", {"review_status": "unknown", "fail_closed": True,
                       "warning": True}, as_of=d(-10), next_review="2026-13-01")
case("next_review 为未来", {"overdue": False, "review_status": "ok"}, as_of=d(-10), next_review=d(90))


def run():
    ok = fail = 0
    for name, expect, kw in CASES:
        got = review_meta(today=T, **kw)
        bad = []
        for k, v in expect.items():
            if k == "warning":
                if (got["warning"] is not None) != v:
                    bad.append(f"warning期望{v}实际{got['warning']!r}")
            elif got.get(k) != v:
                bad.append(f"{k}期望{v}实际{got.get(k)!r}")
        if bad:
            fail += 1
            print(f"FAIL  {name}: " + "; ".join(bad))
        else:
            ok += 1
            print(f"pass  {name}")

    # 一致性判据：旧实现（fresh=ok / overdue=true）与新实现必须报出差异
    old_fresh = {"hubs": [{"hub_key": "UDI全球标识枢纽", "overdue": True, "review_status": None}]}
    old_search_bad = {"results": [{"hub_key": "UDI全球标识枢纽", "overdue": None, "review_status": None}]}
    probs = assert_consistent(old_fresh, old_search_bad)
    print(("pass  " if probs else "FAIL  ") + "一致性检查能抓住旧搜索接口缺字段")
    ok, fail = (ok + 1, fail) if probs else (ok, fail + 1)

    print(f"\nTOTAL {ok} passed / {fail} failed")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
