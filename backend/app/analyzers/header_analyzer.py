import re
from email.utils import parseaddr

from app.models import EmailPayload, Severity, Signal, SignalCategory

# Well-known brand names whose display names are commonly spoofed.
# Maps lowercase brand keyword → canonical domain(s).
_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "hotmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "irs": ["irs.gov"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com"],
}


def _extract_domain(address: str) -> str:
    _, email = parseaddr(address)
    if "@" in email:
        return email.split("@", 1)[1].lower().strip()
    return ""


def _spf_result(received_spf: str | None) -> str:
    if not received_spf:
        return "none"
    match = re.match(r"\s*(\w+)", received_spf)
    return match.group(1).lower() if match else "none"


def _auth_result_field(auth_results: str | None, field: str) -> str:
    """Extract result for a given field (spf/dkim/dmarc) from Authentication-Results header."""
    if not auth_results:
        return "none"
    pattern = rf"{field}=(\w+)"
    match = re.search(pattern, auth_results, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def _check_display_name_spoof(from_address: str) -> Signal | None:
    display_name, email = parseaddr(from_address)
    if not display_name or not email:
        return None

    sender_domain = _extract_domain(from_address)
    name_lower = display_name.lower().replace(" ", "")

    for brand, legit_domains in _BRAND_DOMAINS.items():
        if brand in name_lower and sender_domain not in legit_domains:
            return Signal(
                name="Display Name Spoofing",
                category=SignalCategory.HEADERS,
                severity=Severity.HIGH,
                weight=20,
                description=(
                    f'Sender claims to be "{display_name}" but the actual sending domain '
                    f'"{sender_domain}" is not associated with {brand.title()}. '
                    "This is a classic phishing technique."
                ),
            )
    return None


def analyze(payload: EmailPayload) -> list[Signal]:
    signals: list[Signal] = []

    # SPF check
    spf = _spf_result(payload.received_spf)
    if spf == "fail":
        signals.append(
            Signal(
                name="SPF Authentication Failed",
                category=SignalCategory.HEADERS,
                severity=Severity.HIGH,
                weight=25,
                description=(
                    "The sending mail server is not authorized to send email for this domain. "
                    "This is a strong indicator that the sender address has been forged."
                ),
            )
        )
    elif spf == "softfail":
        signals.append(
            Signal(
                name="SPF Soft Fail",
                category=SignalCategory.HEADERS,
                severity=Severity.MEDIUM,
                weight=12,
                description=(
                    "The domain's SPF policy suggests this server is not authorized to send on its behalf. "
                    "The domain owner considers this suspicious but not definitive."
                ),
            )
        )

    # DKIM check
    dkim = _auth_result_field(payload.authentication_results, "dkim")
    if dkim == "fail":
        signals.append(
            Signal(
                name="DKIM Signature Invalid",
                category=SignalCategory.HEADERS,
                severity=Severity.HIGH,
                weight=15,
                description=(
                    "The DKIM cryptographic signature does not match. "
                    "The message may have been tampered with in transit, or the sender identity is spoofed."
                ),
            )
        )

    # DMARC check
    dmarc = _auth_result_field(payload.authentication_results, "dmarc")
    if dmarc == "fail":
        signals.append(
            Signal(
                name="DMARC Policy Violation",
                category=SignalCategory.HEADERS,
                severity=Severity.HIGH,
                weight=15,
                description=(
                    "The message failed DMARC evaluation. "
                    "The domain owner's published policy flags this email as potentially fraudulent."
                ),
            )
        )

    # Display name spoof
    spoof = _check_display_name_spoof(payload.from_address)
    if spoof:
        signals.append(spoof)

    # Reply-To mismatch
    if payload.reply_to:
        from_domain = _extract_domain(payload.from_address)
        reply_domain = _extract_domain(payload.reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            signals.append(
                Signal(
                    name="Reply-To Domain Mismatch",
                    category=SignalCategory.HEADERS,
                    severity=Severity.MEDIUM,
                    weight=15,
                    description=(
                        f'The email is from "{from_domain}" but replies would go to "{reply_domain}". '
                        "Attackers use this to intercept your reply without controlling the spoofed domain."
                    ),
                )
            )

    return signals
