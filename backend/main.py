from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.enrichment import (
    router as enrichment_router,
)
from backend.api.findings import (
    router as findings_router,
)
from backend.api.risks import (
    router as risks_router,
)
from backend.api.scans import (
    router as scans_router,
)


app = FastAPI(
    title="VulnVerify API",
    version="0.1.0",
)


# Local development CORS.
#
# The frontend is served separately (Vite default port 5173), so the
# browser treats API calls as cross-origin and blocks them without
# these headers. Origins are pinned to the local frontend dev server
# rather than "*", and credentials are deliberately left disabled --
# this API uses no cookies or auth headers.
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=[
        "GET",
        "POST",
        "OPTIONS",
    ],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": (
            "VulnVerify backend is running"
        )
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


app.include_router(
    scans_router,
    prefix="/api/v1",
)

app.include_router(
    findings_router,
    prefix="/api/v1",
)

app.include_router(
    risks_router,
    prefix="/api/v1",
)

app.include_router(
    enrichment_router,
    prefix="/api/v1",
)