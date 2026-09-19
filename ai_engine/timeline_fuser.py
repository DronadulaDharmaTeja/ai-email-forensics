
from pathlib import Path
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional
import json


VERSION = "1.0"


def parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Parse an email timestamp into a timezone-aware UTC datetime.
    """

    if not value:
        return None

    if isinstance(value, datetime):
        dt = value
    else:
        value = str(value).strip()

        try:
            dt = parsedate_to_datetime(value)
        except Exception:
            return None

    if dt.tzinfo is None:
        return None

    return dt.astimezone(timezone.utc)


def to_iso8601(dt: Optional[datetime]) -> Optional[str]:
    """
    Convert datetime to UTC ISO-8601 string.
    """

    if dt is None:
        return None

    return dt.astimezone(timezone.utc).isoformat()


def extract_email_timestamp(
    evidence: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Extract the primary email timestamp.

    Priority:
        1. email.date
        2. headers.Date
    """

    email = evidence.get("email", {})
    headers = evidence.get("headers", {})

    candidates = [
        ("email.date", email.get("date")),
        ("headers.Date", headers.get("Date")),
    ]

    for source, value in candidates:

        if not value:
            continue

        parsed = parse_timestamp(value)

        if parsed is not None:
            return {
                "timestamp": to_iso8601(parsed),
                "timestamp_source": source,
                "original_timestamp": str(value),
                "parse_status": "PARSED",
            }

    return {
        "timestamp": None,
        "timestamp_source": None,
        "original_timestamp": None,
        "parse_status": "MISSING_OR_INVALID",
    }


def extract_received_events(
    evidence: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Extract routing timestamps when Received hops are available.
    """

    routing = evidence.get("routing", {})
    received_hops = routing.get("received_hops", [])

    events = []

    if not isinstance(received_hops, list):
        return events

    for index, hop in enumerate(received_hops):

        if not isinstance(hop, dict):
            continue

        timestamp_value = (
            hop.get("timestamp")
            or hop.get("date")
            or hop.get("received")
        )

        parsed = parse_timestamp(timestamp_value)

        if parsed is None:
            continue

        events.append({
            "event_type": "RECEIVED_HOP",
            "timestamp": to_iso8601(parsed),
            "timestamp_source": "routing.received_hops",
            "hop_index": index,
            "original_timestamp": str(timestamp_value),
            "parse_status": "PARSED",
            "from": hop.get("from"),
            "by": hop.get("by"),
            "with": hop.get("with"),
            "id": hop.get("id"),
        })

    return events


def build_email_event(
    evidence: Dict[str, Any],
    source_file: Optional[str] = None,
) -> Dict[str, Any]:

    email = evidence.get("email", {})
    headers = evidence.get("headers", {})
    evidence_meta = evidence.get("evidence", {})

    timestamp_info = extract_email_timestamp(evidence)

    email_id = None

    if source_file:
        email_id = Path(source_file).name.replace(
            "_forensic.json",
            ""
        )

    return {
        "event_type": "EMAIL_DATE",
        "event_id": (
            f"{email_id}:EMAIL_DATE"
            if email_id
            else "EMAIL_DATE"
        ),
        "email_id": email_id,
        "timestamp": timestamp_info["timestamp"],
        "timestamp_source": timestamp_info["timestamp_source"],
        "original_timestamp": timestamp_info["original_timestamp"],
        "parse_status": timestamp_info["parse_status"],
        "sender": email.get("from"),
        "recipient": email.get("to"),
        "reply_to": email.get("reply_to"),
        "subject": email.get("subject"),
        "message_id": headers.get("Message-ID"),
        "source_file": source_file,
        "evidence_sha256": evidence_meta.get("sha256"),
        "provenance": {
            "source_type": "FORENSIC_EVIDENCE",
            "source_file": source_file,
            "read_only": True,
        },
    }


def fuse_email_timeline(
    evidence: Dict[str, Any],
    source_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a timeline for a single email.
    """

    events = []

    primary_event = build_email_event(
        evidence,
        source_file=source_file,
    )

    if primary_event["timestamp"] is not None:
        events.append(primary_event)

    received_events = extract_received_events(evidence)

    for event in received_events:

        event["email_id"] = primary_event.get("email_id")
        event["subject"] = evidence.get(
            "email",
            {}
        ).get("subject")

        event["source_file"] = source_file

        event["provenance"] = {
            "source_type": "FORENSIC_EVIDENCE",
            "source_file": source_file,
            "read_only": True,
        }

        events.append(event)

    events.sort(
        key=lambda x: x.get("timestamp") or ""
    )

    return {
        "timeline_version": VERSION,
        "email_id": primary_event.get("email_id"),
        "event_count": len(events),
        "events": events,
        "metadata": {
            "received_hops_available": len(received_events) > 0,
            "timestamp_sources": sorted(
                {
                    event.get("timestamp_source")
                    for event in events
                    if event.get("timestamp_source")
                }
            ),
            "read_only": True,
            "source_type": "FORENSIC_EVIDENCE",
        },
    }


def fuse_directory(
    forensic_directory: str,
) -> Dict[str, Any]:
    """
    Build a global chronological timeline.
    """

    directory = Path(forensic_directory)

    files = sorted(
        directory.glob("email_*_forensic.json")
    )

    all_events = []
    processed = 0
    errors = []

    for path in files:

        try:
            with open(
                path,
                "r",
                encoding="utf-8"
            ) as f:
                evidence = json.load(f)

            timeline = fuse_email_timeline(
                evidence,
                source_file=str(path),
            )

            all_events.extend(
                timeline["events"]
            )

            processed += 1

        except Exception as exc:

            errors.append({
                "file": str(path),
                "error": str(exc),
            })

    all_events.sort(
        key=lambda x: x.get("timestamp") or ""
    )

    return {
        "timeline_version": VERSION,
        "summary": {
            "files_discovered": len(files),
            "files_processed": processed,
            "event_count": len(all_events),
            "error_count": len(errors),
        },
        "events": all_events,
        "errors": errors,
        "metadata": {
            "source_directory": str(directory),
            "read_only": True,
            "source_type": "FORENSIC_EVIDENCE",
        },
    }


def build_timeline(
    forensic_directory: str,
) -> Dict[str, Any]:
    """
    Public API for timeline generation.
    """

    return fuse_directory(forensic_directory)
