# -*- coding: utf-8 -*-
"""P0-1 整改方案：MedXpert 统一时效元数据（review_status / overdue），fail-closed。

设计要点
1. 单一函数 review_meta() 同时算 as_of 与 next_review，四个接口只许调它。
2. overdue 与 freshness 不能互相掩盖：取二者较严者作为 effective_risk。
3. 任何解析失败（缺失/格式异常/未来日期）一律 fail-closed，绝不返回 "ok"。
4. warning 文本必须同时说明两个事实（几天未复核 + 复核计划状态），不合并成一句模糊话。
"""
from __future__ import annotations

import datetime as _dt

POLICY = {"ok_days": 90, "aging_days": 180}

_RISK_ORDER = {"ok": 0, "low": 1, "medium": 2, "high": 3, "unknown": 4}


def _parse_date(v):
    """严格 ISO 日期。返回 (date, None) 或 (None, 原因)。"""
    if v is None:
        return None, "missing"
    if not isinstance(v, str) or not v.strip():
        return None, "empty"
    s = v.strip()
    if len(s) != 10:
        return None, "not_iso_date"
    try:
        return _dt.date.fromisoformat(s), None
    except ValueError:
        return None, "invalid_date"


def review_meta(as_of, next_review, verified="unknown", copyright_="unknown",
                today=None, policy=None):
    """统一的时效/复核元数据。四接口共用。

    返回字段：as_of, age_days, freshness, next_review, overdue, review_status,
              verified, copyright, effective_risk, warning, reasons, fail_closed
    review_status ∈ {ok, due, overdue, unscheduled, unknown, invalid}
    """
    pol = policy or POLICY
    today = today or _dt.date.today()
    reasons = []

    d, err = _parse_date(as_of)
    dnr, nr_err = _parse_date(next_review)

    # ---- as_of 侧 ----
    if d is None:
        freshness, age_days = "unknown", None
        reasons.append(f"as_of {err}")
        as_of_status = "unknown"
    elif d > today:
        freshness, age_days = "invalid", (d - today).days
        reasons.append("as_of 在未来")
        as_of_status = "invalid"
    else:
        age_days = (today - d).days
        if age_days <= pol["ok_days"]:
            freshness = "ok"
        elif age_days <= pol["aging_days"]:
            freshness = "aging"
        else:
            freshness = "stale"
        as_of_status = freshness

    # ---- next_review 侧 ----
    if next_review is None:
        overdue, nr_status = False, "unscheduled"
        reasons.append("next_review 缺失（无复核计划）")
    elif dnr is None:
        overdue, nr_status = False, "unknown"
        reasons.append(f"next_review {nr_err}")
    elif dnr < today:
        overdue, nr_status = True, "overdue"
        reasons.append(f"next_review 已逾期 {(today - dnr).days} 天")
    elif dnr == today:
        overdue, nr_status = False, "due"
        reasons.append("next_review 为今日（到期）")
    else:
        overdue, nr_status = False, "ok"

    # ---- 合成 ----
    if nr_status in ("unknown",):
        review_status = "unknown"
    elif as_of_status == "invalid":
        review_status = "invalid"
    elif as_of_status == "unknown":
        review_status = "unknown"
    elif overdue:
        review_status = "overdue"
    elif nr_status == "due":
        review_status = "due"
    elif nr_status == "unscheduled":
        review_status = "unscheduled"
    else:
        review_status = "ok"

    fail_closed = review_status in ("unknown", "invalid")

    fr_risk = {"ok": "ok", "aging": "medium", "stale": "high",
               "unknown": "unknown", "invalid": "unknown"}[freshness]
    risk = fr_risk
    if overdue:
        risk = "high"
    if fail_closed:
        risk = "unknown"
    if _RISK_ORDER[risk] < _RISK_ORDER[fr_risk]:
        risk = fr_risk

    parts = []
    if age_days is not None and freshness != "ok":
        parts.append(f"as_of {as_of}，已 {age_days} 天未复核（freshness={freshness}）")
    if overdue:
        parts.append(f"next_review {next_review} 已逾期（overdue=true），即使 freshness={freshness} 也须复核")
    elif nr_status == "due":
        parts.append(f"next_review {next_review} 今日到期")
    elif nr_status == "unknown":
        parts.append(f"next_review 标注异常（{nr_err}），无法判断是否逾期")
    elif nr_status == "unscheduled":
        parts.append("未登记 next_review，无法判断复核排期")
    if freshness in ("unknown", "invalid"):
        parts.append("as_of 缺失或异常，内容时效不可证，按不可用处理")

    warning = "；".join(parts) if parts else None

    return {
        "as_of": as_of,
        "age_days": age_days,
        "freshness": freshness,
        "next_review": next_review,
        "overdue": overdue,
        "review_status": review_status,
        "verified": verified,
        "copyright": copyright_,
        "effective_risk": risk,
        "warning": warning,
        "reasons": reasons,
        "fail_closed": fail_closed,
    }


def assert_consistent(freshness_payload, search_payload):
    """验收判据：同一枢纽在时效接口与检索接口上的风险状态必须一致。"""
    problems = []
    by_key = {r["hub_key"]: r for r in freshness_payload["hubs"]}
    for hit in search_payload.get("results", []):
        k = hit["hub_key"]
        f = by_key.get(k)
        if not f:
            continue
        if f.get("overdue") != hit.get("overdue"):
            problems.append(f"{k}: freshness接口 overdue={f.get('overdue')} vs 检索接口 overdue={hit.get('overdue')}")
        if f.get("review_status") != hit.get("review_status"):
            problems.append(f"{k}: review_status 不一致")
    return problems
