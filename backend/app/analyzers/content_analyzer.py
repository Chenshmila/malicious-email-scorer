import json
import logging

import anthropic

from app.config import settings
from app.models import EmailPayload, Severity, Signal, SignalCategory

logger = logging.getLogger(__name__)

_ANALYSIS_TOOL = {
    "name": "report_signals",
    "description": "Report detected phishing/malicious signals in the email.",
    "input_schema": {
        "type": "object",
        "properties": {
            "signals": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                        "weight": {"type": "integer", "minimum": 5, "maximum": 30},
                        "description": {"type": "string"},
                    },
                    "required": ["name", "severity", "weight", "description"],
                },
            }
        },
        "required": ["signals"],
    },
}

_SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in phishing and social engineering detection.
Analyze the provided email and identify any malicious signals present in its content.

Focus exclusively on content-level signals (not headers or URLs, those are analyzed separately):
- Urgency or fear-inducing language ("act now", "account suspended", "verify immediately")
- Requests for credentials, passwords, credit card numbers, or sensitive personal data
- Brand impersonation through tone, language patterns, or claimed identity
- Social engineering tactics (false authority, reward bait, threat of consequence, sympathy manipulation)
- Grammar/phrasing inconsistencies typical of translated phishing templates
- Linguistic integrity: Analyze the grammatical quality and syntax of the email body.
  Look for signs of Machine Translation such as wrong verb tense or gender agreement,
  unnatural or stilted phrasing, broken sentence structure, or vocabulary mismatches
  that suggest the text was auto-translated from another language. If poor linguistic
  integrity is detected, report it as a signal named exactly "Linguistic Anomaly Detected"
  with severity "medium" and a weight between 10 and 15.

For each signal found, assign:
- A clear name (3-6 words)
- Severity: low / medium / high / critical
- Weight: integer 5-30 representing how much this signal contributes to a maliciousness score
- A concise description explaining what you found and why it is suspicious (1-2 sentences)

Only report signals that are actually present. If the email is legitimate, return an empty signals list.
Do not flag routine transactional language or standard newsletter content as suspicious."""


def analyze(payload: EmailPayload) -> list[Signal]:
    """Call Claude to detect content-level social engineering signals.

    Returns an empty list on any API failure so rule-based analysis still produces a result.
    """
    # subject and plain_body are already anonymized by EmailParser.gs on the client
    email_text = (
        f"Subject: {payload.subject}\n"
        f"From: {payload.from_address}\n\n"
        f"{payload.plain_body}"
    )

    try:
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        response = client.messages.create(
            model=settings.model,
            max_tokens=1024,
            system=_SYSTEM_PROMPT,
            tools=[_ANALYSIS_TOOL],
            tool_choice={"type": "any"},
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze this email for malicious content signals:\n\n{email_text}",
                }
            ],
        )
    except anthropic.APIError as exc:
        logger.warning("Claude API error during content analysis: %s", exc)
        return []

    # Extract the tool_use block
    tool_block = next(
        (block for block in response.content if block.type == "tool_use"),
        None,
    )
    if not tool_block:
        logger.warning("Claude did not return a tool_use block")
        return []

    raw_signals: list[dict] = tool_block.input.get("signals", [])
    signals: list[Signal] = []
    for item in raw_signals:
        try:
            signals.append(
                Signal(
                    name=str(item["name"])[:80],
                    category=SignalCategory.CONTENT,
                    severity=Severity(item["severity"]),
                    weight=int(item["weight"]),
                    description=str(item["description"])[:300],
                )
            )
        except (KeyError, ValueError) as exc:
            logger.debug("Skipping malformed signal from Claude: %s — %s", item, exc)

    return signals
