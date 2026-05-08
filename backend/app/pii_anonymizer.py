import re

# Email addresses
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Phone numbers — covers US/international formats: +1-800-555-0199, (800) 555-0199, 800.555.0199, etc.
_PHONE_RE = re.compile(
    r"(?<!\d)"               # not preceded by a digit
    r"(\+?1[-.\s]?)?"        # optional country code
    r"\(?\d{3}\)?[-.\s]?"    # area code
    r"\d{3}[-.\s]?"          # exchange
    r"\d{4}"
    r"(?!\d)"                # not followed by a digit
)

# Names preceded by a common honorific
_NAME_RE = re.compile(
    r"\b(?:Mr\.|Mrs\.|Ms\.|Miss|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b"
)


def anonymize(text: str) -> str:
    """Replace PII patterns in *text* with placeholder tokens."""
    text = _EMAIL_RE.sub("[EMAIL]", text)
    text = _PHONE_RE.sub("[PHONE]", text)
    text = _NAME_RE.sub("[NAME]", text)
    return text
