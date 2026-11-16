"""5x5 likelihood and impact matrix.

Scores are the product of the two grades, so the range is 1-25. Severity
bands are fixed here rather than stored per row: changing a threshold only
changes presentation, and every register recomputes consistently. The bands
follow the common consulting split of low / medium / high / critical.
"""

from __future__ import annotations

MATRIX_MIN = 1
MATRIX_MAX = 5

LIKELIHOOD_LABELS = {
    1: "极少",
    2: "不太可能",
    3: "可能",
    4: "很可能",
    5: "几乎确定",
}

LIKELIHOOD_DESCRIPTIONS = {
    1: "现有条件下五年内基本不会发生",
    2: "每年最多一次，且有明显前置条件",
    3: "每年数次，行业内常见",
    4: "每月都可能发生，已有先例",
    5: "持续暴露，随时可能触发",
}

IMPACT_LABELS = {
    1: "可忽略",
    2: "轻微",
    3: "中等",
    4: "重大",
    5: "严重",
}

IMPACT_DESCRIPTIONS = {
    1: "无业务中断，无外部可见影响",
    2: "局部功能受影响，当日可恢复",
    3: "核心业务短时中断，需数日恢复",
    4: "核心业务长时间中断，产生监管或财务影响",
    5: "业务停摆、重大数据泄露或不可恢复损失",
}

SEVERITY_LABELS = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
}

SEVERITY_ORDER = ("low", "medium", "high", "critical")

# Default acceptable residual score when an engagement has not set a preference.
DEFAULT_APPETITE = 9

# Upper bound (inclusive) of each band.
_UPPER_BOUNDS = (("low", 4), ("medium", 9), ("high", 15), ("critical", 25))


def severity_for(score: int) -> str:
    for label, upper in _UPPER_BOUNDS:
        if score <= upper:
            return label
    return "critical"
