from datetime import datetime, timedelta, timezone
import secrets
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


# ============================================================
# TEMPORARY OTP STORAGE
# ============================================================

otp_store = {}

OTP_EXPIRY_MINUTES = 5


# ============================================================
# REQUEST MODELS
# ============================================================

class SendOTPRequest(BaseModel):
    identifier: str


class VerifyOTPRequest(BaseModel):
    identifier: str
    otp: str


# ============================================================
# VALIDATION
# ============================================================

def validate_identifier(identifier: str) -> str:
    identifier = identifier.strip()

    # Email
    if re.fullmatch(
        r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
        identifier,
    ):
        return identifier

    # Indian mobile number
    if re.fullmatch(r"^(?:\+91)?[6-9]\d{9}$", identifier):
        return identifier

    raise HTTPException(
        status_code=400,
        detail="Enter a valid email address or mobile number.",
    )


# ============================================================
# SEND OTP
# ============================================================

@router.post("/send-otp")
def send_otp(request: SendOTPRequest):

    identifier = validate_identifier(request.identifier)

    # Generate secure 6-digit OTP
    otp = f"{secrets.randbelow(1_000_000):06d}"

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=OTP_EXPIRY_MINUTES
    )

    otp_store[identifier] = {
        "otp": otp,
        "expires_at": expires_at,
        "attempts": 0,
    }

    # Development only
    print("\n========================================")
    print("             OTP GENERATED")
    print("========================================")
    print(f"Identifier : {identifier}")
    print(f"OTP        : {otp}")
    print(f"Expires    : {expires_at.isoformat()}")
    print("========================================\n")

    return {
        "status": "success",
        "message": "OTP generated successfully.",
        "expires_in_seconds": OTP_EXPIRY_MINUTES * 60,
    }


# ============================================================
# VERIFY OTP
# ============================================================

@router.post("/verify-otp")
def verify_otp(request: VerifyOTPRequest):

    identifier = validate_identifier(request.identifier)

    record = otp_store.get(identifier)

    if record is None:
        raise HTTPException(
            status_code=400,
            detail="OTP not found. Please request a new OTP.",
        )

    # Limit attempts
    if record["attempts"] >= 5:
        del otp_store[identifier]

        raise HTTPException(
            status_code=429,
            detail="Too many incorrect attempts. Request a new OTP.",
        )

    # Check expiration
    if datetime.now(timezone.utc) > record["expires_at"]:
        del otp_store[identifier]

        raise HTTPException(
            status_code=400,
            detail="OTP has expired. Please request a new OTP.",
        )

    # Check OTP
    if not secrets.compare_digest(
        str(request.otp),
        str(record["otp"]),
    ):
        record["attempts"] += 1

        raise HTTPException(
            status_code=401,
            detail="Invalid OTP.",
        )

    # Successful verification
    del otp_store[identifier]

    return {
        "status": "success",
        "authenticated": True,
        "message": "OTP verified successfully.",
        "identifier": identifier,
    }