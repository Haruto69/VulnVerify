from fastapi import FastAPI

from backend.api.scans import router as scans_router


app = FastAPI(
    title="VulnVerify API",
    version="0.1.0"
)


@app.get("/")
def root():
    return {"message": "VulnVerify backend is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(
    scans_router,
    prefix="/api/v1"
)