from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from database.cases_repository import get_case


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="AI Email Forensics API",
    version="1.0.0",
    description="API for the AI Email Forensics Investigation System",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "AI Email Forensics API",
        "version": "1.0.0",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "AI Email Forensics API",
    }


# ============================================================
# CASE RETRIEVAL
# ============================================================

@app.get("/cases/{case_id}")
def get_case_api(case_id: str):
    case = get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail=f"Case not found: {case_id}",
        )

    return case


# ============================================================
# SERVER ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )