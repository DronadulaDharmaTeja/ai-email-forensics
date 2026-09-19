from mcp.server.fastmcp import FastMCP

import copy
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# EXISTING FORENSIC COMPONENTS
# ============================================================

from parsers.email_parser import parse_eml
from database.cases_repository import get_case


# ============================================================
# MCP SERVER
# ============================================================

mcp = FastMCP("Email Forensics MCP")


# ============================================================
# HEALTH CHECK
# ============================================================

@mcp.tool()
def health_check() -> dict:
    """Check whether the Email Forensics MCP server is working."""

    return {
        "status": "ok",
        "server": "Email Forensics MCP"
    }


# ============================================================
# EMAIL PARSER
# ============================================================

@mcp.tool()
def parse_email(file_path: str) -> dict:
    """Parse an EML file using the existing forensic email parser."""

    result = parse_eml(file_path)

    return result


# ============================================================
# HEADER ANALYSIS
# ============================================================

@mcp.tool()
def analyze_headers(file_path: str) -> dict:
    """Extract and summarize email headers using the existing forensic parser."""

    result = parse_eml(file_path)

    headers = result.get("headers", {})

    important_headers = {
        "From": headers.get("From", ""),
        "To": headers.get("To", ""),
        "Subject": headers.get("Subject", ""),
        "Date": headers.get("Date", ""),
        "Message-ID": headers.get("Message-ID", ""),
        "Reply-To": headers.get("Reply-To", ""),
        "Received": headers.get("Received", ""),
        "Return-Path": headers.get("Return-Path", ""),
        "Authentication-Results": headers.get(
            "Authentication-Results",
            ""
        ),
        "DKIM-Signature": headers.get(
            "DKIM-Signature",
            ""
        ),
        "Received-SPF": headers.get(
            "Received-SPF",
            ""
        ),
    }

    return {
        "source_file": result["evidence"]["source_file"],
        "filename": result["evidence"]["filename"],
        "sha256": result["evidence"]["sha256"],
        "header_count": len(headers),
        "headers": headers,
        "important_headers": important_headers,
    }


# ============================================================
# URL ANALYSIS
# ============================================================

@mcp.tool()
def analyze_url(url: str) -> dict:
    """
    Analyze URL structure without executing or contacting the URL.
    """

    raw_url = str(url).strip()

    # Extract HTTP/HTTPS URL from surrounding text.
    match = re.search(
        r"https?://[^\s<>\")]+",
        raw_url,
        re.IGNORECASE
    )

    if not match:
        return {
            "valid_url": False,
            "input": raw_url,
            "reason": "No HTTP/HTTPS URL found."
        }

    normalized_url = match.group(0).rstrip(
        ".,;:!?"
    )

    # Handle Markdown link syntax.
    markdown_match = re.search(
        r"\]\((https?://[^)\s]+)\)",
        raw_url,
        re.IGNORECASE
    )

    if markdown_match:
        normalized_url = markdown_match.group(1).rstrip(
            ".,;:!?"
        )

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""

    indicators = []

    if parsed.scheme.lower() == "http":
        indicators.append("HTTP_NOT_HTTPS")

    if parsed.port is not None:
        indicators.append("NON_DEFAULT_PORT")

    if "@" in parsed.netloc:
        indicators.append("USERINFO_PRESENT")

    if len(hostname.split(".")) > 4:
        indicators.append("DEEP_SUBDOMAIN")

    if len(normalized_url) > 200:
        indicators.append("LONG_URL")

    if parsed.query:
        indicators.append("QUERY_PRESENT")

    return {
        "valid_url": bool(
            parsed.scheme and parsed.netloc
        ),
        "executed": False,
        "normalized_url": normalized_url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "indicators": indicators,
        "analysis_note": (
            "Structural observations only. "
            "These indicators do not independently establish "
            "that a URL is malicious or phishing."
        )
    }


# ============================================================
# DETERMINISTIC RISK ENGINE
# ============================================================

@mcp.tool()
def get_case_tool(case_id: str) -> dict:
    result = get_case(case_id)
    if result is None:
        return {"found": False, "case_id": case_id}
    return {"found": True, "case": result}


@mcp.tool()
def calculate_risk(evidence: dict) -> dict:
    """
    Calculate deterministic forensic risk using a derived
    scoring view.

    The original evidence object is never modified.
    """

    from ai_engine.multi_agent_debate.evidence_scoring import (
        score_evidence
    )

    # --------------------------------------------------------
    # Preserve original evidence
    # --------------------------------------------------------

    scoring_evidence = copy.deepcopy(evidence)

    # --------------------------------------------------------
    # Extract email body
    # --------------------------------------------------------

    body = (
        scoring_evidence
        .get("email", {})
        .get("body", {})
        .get("text", "")
    )

    # --------------------------------------------------------
    # Extract HTTP/HTTPS URLs
    # --------------------------------------------------------

    url_strings = re.findall(
        r"(?<![\w\]\)])https?://[^\s<>\")]+",
        str(body),
        re.IGNORECASE
    )

    # --------------------------------------------------------
    # Normalize and deduplicate URLs
    # --------------------------------------------------------

    normalized_urls = []

    for url in url_strings:

        url = url.rstrip(
            ".,;:!?"
        )

        if url not in normalized_urls:
            normalized_urls.append(url)

    # --------------------------------------------------------
    # Create the structure expected by score_evidence()
    #
    # IMPORTANT:
    # score_evidence() expects:
    #
    # {
    #     "url": "...",
    #     "risk": "..."
    # }
    # --------------------------------------------------------

    scoring_evidence["urls"] = [
        {
            "url": url,
            "risk": "LOW"
        }
        for url in normalized_urls
    ]

    # --------------------------------------------------------
    # Calculate deterministic risk
    # --------------------------------------------------------

    result = score_evidence(
        scoring_evidence
    )

    # --------------------------------------------------------
    # Provenance metadata
    # --------------------------------------------------------

    result["derived_url_count"] = len(
        normalized_urls
    )

    result["original_urls_field_present"] = (
        "urls" in evidence
    )

    result["original_evidence_modified"] = False

    return result


# ============================================================
# SERVER ENTRY POINT
# ============================================================

if __name__ == "__main__":
    mcp.run()