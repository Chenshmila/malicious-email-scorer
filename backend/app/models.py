from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SignalCategory(str, Enum):
    HEADERS = "headers"
    URLS = "urls"
    CONTENT = "content"
    ATTACHMENTS = "attachments"


class Signal(BaseModel):
    name: str
    category: SignalCategory
    severity: Severity
    weight: int
    description: str


class AttachmentInfo(BaseModel):
    name: str = Field(max_length=256)
    mime_type: str = Field(max_length=128)


class EmailPayload(BaseModel):
    subject: str = Field(default="", max_length=998)
    from_address: str = Field(max_length=256)
    reply_to: Optional[str] = Field(default=None, max_length=256)
    plain_body: str = Field(default="", max_length=4000)
    received_spf: Optional[str] = Field(default=None, max_length=512)
    authentication_results: Optional[str] = Field(default=None, max_length=1024)
    dkim_signature: Optional[str] = Field(default=None, max_length=1024)
    attachments: list[AttachmentInfo] = Field(default_factory=list, max_length=20)


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    verdict: str
    summary: str
    signals: list[Signal]
