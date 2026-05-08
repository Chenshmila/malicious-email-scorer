import json
import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.analyzers import content_analyzer, header_analyzer, scorer, url_analyzer
from app.models import AnalysisResult, EmailPayload
from app.security import require_api_key
from app import cache_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Email scorer backend starting")
    yield
    logger.info("Email scorer backend shutting down")


app = FastAPI(
    title="Malicious Email Scorer",
    version="1.0.0",
    docs_url=None,   # disable Swagger UI in production; enable locally if needed
    redoc_url=None,
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Google Apps Script sends requests from Google's servers; CORS is not strictly
# needed for UrlFetchApp but is added for future browser-based clients.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def _log_request(request: Request, call_next: Response) -> Response:
    body = await request.body()
    logger.info(
        "INCOMING %s %s  content-type=%s  body=%d bytes  preview=%r",
        request.method, request.url.path,
        request.headers.get("content-type", "-"),
        len(body),
        body[:120],
    )
    return await call_next(request)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalysisResult,
    dependencies=[Depends(require_api_key)],
)
@limiter.limit("30/minute")
async def analyze(request: Request) -> AnalysisResult:
    raw = await request.body()
    logger.info("raw body (%d bytes): %r", len(raw), raw[:200])

    try:
        payload = EmailPayload.model_validate(json.loads(raw))
    except Exception as exc:
        logger.error("body parse failed: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc))

    cache_key = cache_manager.make_key(payload.subject, payload.plain_body)
    cached = cache_manager.get(cache_key)
    if cached is not None:
        logger.info("cache hit key=%s score=%d", cache_key[:16], cached.score)
        return cached

    start = time.perf_counter()

    header_signals = header_analyzer.analyze(payload)
    url_signals = url_analyzer.analyze(payload)
    content_signals = content_analyzer.analyze(payload)

    all_signals = header_signals + url_signals + content_signals
    result = scorer.score(all_signals)

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    logger.info(
        "analyzed email score=%d risk=%s signals=%d elapsed_ms=%d",
        result.score,
        result.risk_level,
        len(all_signals),
        elapsed_ms,
    )

    cache_manager.set(cache_key, result)
    return result
