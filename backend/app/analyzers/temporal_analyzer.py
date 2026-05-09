from email.utils import parsedate_to_datetime

from app.models import EmailPayload, Severity, Signal, SignalCategory

# Financial and government brands that operate on predictable business-hour
# schedules. Automated alerts sent deep in the night or on weekends are a
# meaningful anomaly for these senders.
_BUSINESS_HOUR_BRANDS: frozenset[str] = frozenset({
    "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "amex", "hsbc", "barclays", "paypal", "fidelity", "schwab", "intuit",
    "irs", "ssa",
})

_BUSINESS_START = 6   # 06:00 sender-local time
_BUSINESS_END   = 22  # 22:00 sender-local time


def analyze(payload: EmailPayload) -> list[Signal]:
    if not payload.email_date:
        return []

    try:
        dt = parsedate_to_datetime(payload.email_date)
    except Exception:
        return []

    from_lower = payload.from_address.lower()
    if not any(brand in from_lower for brand in _BUSINESS_HOUR_BRANDS):
        return []

    is_weekend   = dt.weekday() >= 5  # Saturday=5, Sunday=6
    is_off_hours = dt.hour < _BUSINESS_START or dt.hour >= _BUSINESS_END

    if not (is_weekend or is_off_hours):
        return []

    tz_name  = str(dt.tzinfo) if dt.tzinfo else "UTC"
    time_str = dt.strftime("%H:%M") + f" {tz_name}"
    day_str  = dt.strftime("%A")

    context = f"sent on {day_str} at {time_str}" if is_weekend else f"sent at {time_str} (outside business hours)"

    return [Signal(
        name="Temporal Anomaly Detected",
        category=SignalCategory.HEADERS,
        severity=Severity.MEDIUM,
        weight=10,
        description=(
            f"Email purportedly from a financial institution was {context}. "
            "Legitimate automated alerts from banks and payment services are "
            "typically sent during standard business hours."
        ),
    )]
