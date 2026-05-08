from app.models import AnalysisResult, RiskLevel, Signal


def _risk_level(score: int) -> RiskLevel:
    if score >= 81:
        return RiskLevel.CRITICAL
    if score >= 56:
        return RiskLevel.HIGH
    if score >= 31:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _verdict(risk: RiskLevel, score: int) -> str:
    if risk == RiskLevel.CRITICAL:
        return "Almost Certainly Malicious"
    if risk == RiskLevel.HIGH:
        return "Likely Phishing or Scam"
    if risk == RiskLevel.MEDIUM:
        return "Suspicious — Proceed with Caution"
    return "Appears Legitimate"


def _summary(risk: RiskLevel, signals: list[Signal]) -> str:
    if not signals:
        return "No threat signals were detected. This email appears to be legitimate."

    top = sorted(signals, key=lambda s: s.weight, reverse=True)[:3]
    top_names = ", ".join(f'"{s.name}"' for s in top)

    if risk == RiskLevel.CRITICAL:
        return (
            f"This email shows {len(signals)} strong indicator(s) of a malicious campaign, "
            f"including {top_names}. Do not click any links, open attachments, or provide any information."
        )
    if risk == RiskLevel.HIGH:
        return (
            f"This email exhibits {len(signals)} suspicious indicator(s) consistent with phishing, "
            f"including {top_names}. Exercise extreme caution before taking any action."
        )
    if risk == RiskLevel.MEDIUM:
        return (
            f"This email has {len(signals)} flag(s) that warrant attention, including {top_names}. "
            "Verify the sender through a trusted channel before responding."
        )
    return (
        f"This email has {len(signals)} minor flag(s) including {top_names}, "
        "but does not show strong signs of malicious intent."
    )


def score(signals: list[Signal]) -> AnalysisResult:
    total = min(100, sum(s.weight for s in signals))
    risk = _risk_level(total)
    return AnalysisResult(
        score=total,
        risk_level=risk,
        verdict=_verdict(risk, total),
        summary=_summary(risk, signals),
        signals=signals,
    )
