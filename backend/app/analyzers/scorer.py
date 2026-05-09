from app.models import AnalysisResult, RiskLevel, Severity, Signal, SignalCategory

# Individual signals that always floor the score to CRITICAL on their own.
CRITICAL_INDICATORS: frozenset[str] = frozenset({
    "Lookalike Domain Detected",  # Levenshtein ≤ 2 from brand — url_analyzer
    "Display Name Spoofing",      # Brand in display name, mismatched domain — header_analyzer
})

# Technical authentication failures that confirm the sending server is forged.
_AUTH_FAILURE_SIGNALS: frozenset[str] = frozenset({
    "SPF Authentication Failed",
    "DKIM Signature Invalid",
})

# Signals that confirm the email is impersonating a known brand.
_BRAND_IMPERSONATION_SIGNALS: frozenset[str] = frozenset({
    "Lookalike Domain Detected",
    "Display Name Spoofing",
})

# Severity downgrade applied to AI content signals from verified brand senders.
# Prevents legitimate urgency language from triggering the hard-fail floor.
_VERIFIED_SEVERITY_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.MEDIUM,
    Severity.HIGH: Severity.LOW,
}


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


def score(signals: list[Signal], verified_brand: bool = False) -> AnalysisResult:
    # Verified senders (e.g. real google.com) legitimately use urgent language.
    # Dampen AI content signals to 20% of their original weight so they no longer
    # dominate the score, while remaining visible in the breakdown.
    if verified_brand:
        signals = [
            s.model_copy(update={
                "weight": max(1, round(s.weight * 0.2)),
                "severity": _VERIFIED_SEVERITY_DOWNGRADE.get(s.severity, s.severity),
            })
            if s.category == SignalCategory.CONTENT
            else s
            for s in signals
        ]

    raw_total = min(100, sum(s.weight for s in signals))

    names = frozenset(s.name for s in signals)
    brand_auth_failure = bool(names & _AUTH_FAILURE_SIGNALS) and bool(names & _BRAND_IMPERSONATION_SIGNALS)

    # For verified brands, AI content signals cannot trigger the hard-fail floor —
    # legitimate security emails are expected to use urgent language. Only technical
    # signals (HEADERS, URLS) retain the ability to floor the score.
    has_critical = (
        any(
            s.severity == Severity.CRITICAL or s.name in CRITICAL_INDICATORS
            for s in signals
            if not (verified_brand and s.category == SignalCategory.CONTENT)
        )
        or brand_auth_failure
    )
    total = max(90, raw_total) if has_critical else raw_total

    risk = _risk_level(total)
    return AnalysisResult(
        score=total,
        risk_level=risk,
        verdict=_verdict(risk, total),
        summary=_summary(risk, signals),
        signals=signals,
    )
