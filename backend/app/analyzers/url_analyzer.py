import re
from html.parser import HTMLParser
from urllib.parse import urlparse

import tldextract
from Levenshtein import distance as levenshtein_distance

from app.models import EmailPayload, Severity, Signal, SignalCategory

# Top-brand registered domains to check lookalikes against.
_BRAND_REGISTERED_DOMAINS = [
    # Big tech & cloud
    "paypal.com", "apple.com", "google.com", "microsoft.com", "amazon.com",
    "adobe.com", "dropbox.com", "icloud.com", "github.com", "zoom.us",
    "slack.com", "docusign.com", "salesforce.com",
    # Social & communication
    "netflix.com", "facebook.com", "instagram.com", "linkedin.com", "twitter.com",
    "tiktok.com", "snapchat.com", "whatsapp.com", "spotify.com", "discord.com",
    # Email providers
    "outlook.com", "yahoo.com", "gmail.com", "hotmail.com", "protonmail.com",
    # E-commerce & shipping
    "ebay.com", "walmart.com", "etsy.com",
    "fedex.com", "ups.com", "dhl.com", "usps.com",
    # Banking & finance
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "capitalone.com", "amex.com", "hsbc.com", "barclays.com",
    "fidelity.com", "schwab.com", "intuit.com",
    # Crypto
    "coinbase.com", "binance.com", "kraken.com",
    # Gaming
    "steam.com",
]

# Registered domains of known URL shorteners.
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "short.link", "rebrand.ly", "cutt.ly", "tiny.cc", "shorturl.at", "bl.ink",
}

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]\[)(,]+", re.IGNORECASE
)
_IP_URL_PATTERN = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)", re.IGNORECASE
)


class _AnchorParser(HTMLParser):
    """Collect (href, text) pairs from <a> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = dict(attrs).get("href") or ""
            self._current_href = href.strip()
            self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.anchors.append((self._current_href, text))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)


def _registered_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ""
    except Exception:
        return ""


def _is_lookalike(domain: str) -> str | None:
    """Return the brand being imitated if the domain looks like a known brand, else None."""
    rd = _registered_domain(domain)
    if not rd:
        return None

    for brand_rd in _BRAND_REGISTERED_DOMAINS:
        if rd == brand_rd:
            return None  # Exact match is legitimate
        brand_name = brand_rd.split(".")[0]
        # Levenshtein ≤ 2 on the registered domain catches typos (paypa1.com, gooogle.com)
        if levenshtein_distance(rd.split(".")[0], brand_name) <= 2 and rd != brand_rd:
            return brand_rd
        # Subdomain abuse: brand.com.evil.net
        if brand_rd in domain and rd != brand_rd:
            return brand_rd

    return None


def _extract_urls(text: str) -> list[str]:
    return _URL_PATTERN.findall(text)


def analyze(payload: EmailPayload) -> list[Signal]:
    signals: list[Signal] = []
    body = payload.plain_body

    urls = _extract_urls(body)

    # IP-based URLs
    ip_urls = [u for u in urls if _IP_URL_PATTERN.match(u)]
    if ip_urls:
        signals.append(
            Signal(
                name="IP Address Used in URL",
                category=SignalCategory.URLS,
                severity=Severity.HIGH,
                weight=15,
                description=(
                    f"Found {len(ip_urls)} URL(s) pointing to raw IP addresses "
                    f'(e.g. {ip_urls[0][:60]}). Legitimate services use domain names, '
                    "not bare IPs."
                ),
            )
        )

    # URL shorteners
    shortener_hits = [u for u in urls if _registered_domain(u) in _SHORTENER_DOMAINS]
    if shortener_hits:
        signals.append(
            Signal(
                name="URL Shortener Detected",
                category=SignalCategory.URLS,
                severity=Severity.LOW,
                weight=10,
                description=(
                    f"Found {len(shortener_hits)} shortened URL(s) "
                    f'(e.g. {shortener_hits[0][:60]}). '
                    "Shorteners hide the real destination and are frequently abused in phishing campaigns."
                ),
            )
        )

    # Lookalike domains
    lookalike_hits: list[tuple[str, str]] = []
    seen_domains: set[str] = set()
    for url in urls:
        rd = _registered_domain(url)
        if rd in seen_domains:
            continue
        seen_domains.add(rd)
        brand = _is_lookalike(url)
        if brand:
            lookalike_hits.append((url, brand))

    if lookalike_hits:
        example_url, example_brand = lookalike_hits[0]
        signals.append(
            Signal(
                name="Lookalike Domain Detected",
                category=SignalCategory.URLS,
                severity=Severity.CRITICAL,
                weight=25,
                description=(
                    f"Found a domain that closely resembles {example_brand} "
                    f'(e.g. {example_url[:80]}). '
                    "Attackers register near-identical domains to steal credentials."
                ),
            )
        )

    # Text/href mismatch in HTML anchors — parse from plain body if it contains HTML fragments
    parser = _AnchorParser()
    try:
        parser.feed(body)
    except Exception:
        pass

    for href, text in parser.anchors:
        # Only flag when the visible text looks like a URL/domain
        if not re.search(r"\w+\.\w{2,}", text):
            continue
        href_domain = _registered_domain(href)
        text_domain = _registered_domain(text)
        if href_domain and text_domain and href_domain != text_domain:
            signals.append(
                Signal(
                    name="Misleading Link Text",
                    category=SignalCategory.URLS,
                    severity=Severity.HIGH,
                    weight=20,
                    description=(
                        f'Link displays "{text[:60]}" but actually points to '
                        f'"{urlparse(href).netloc[:60]}". '
                        "This is a deliberate deception technique used in phishing."
                    ),
                )
            )
            break  # One example is enough

    return signals
