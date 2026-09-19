import hashlib
import json
from pathlib import Path

from database.db import execute_query, fetch_one


def calculate_md5(source_file: str, fallback_sha256: str = "") -> str:
    """
    Calculate the actual MD5 hash of the original evidence file.

    If the original file is unavailable, calculate an MD5 value
    from the available SHA-256 string as a fallback.
    """

    if source_file:
        path = Path(source_file)

        if path.exists() and path.is_file():
            md5 = hashlib.md5()

            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    md5.update(chunk)

            return md5.hexdigest()

    return hashlib.md5(
        fallback_sha256.encode("utf-8")
    ).hexdigest()


def insert_case(
    evidence: dict,
    case_id: str,
    threat_score: int = 0,
    threat_level: str = "LOW",
):
    """
    Insert one forensic email case into the existing MySQL cases table.
    """

    email = evidence.get("email", {})
    headers = evidence.get("headers", {})
    evidence_info = evidence.get("evidence", {})

    # ---------------------------------------------------------
    # Email fields
    # ---------------------------------------------------------

    sender = str(email.get("from", "") or "")
    recipient = str(email.get("to", "") or "")
    subject = str(email.get("subject", "") or "")
    date_sent = str(email.get("date", "") or "")

    # ---------------------------------------------------------
    # Body
    # ---------------------------------------------------------

    body = email.get("body", {})

    if isinstance(body, dict):
        body_text = str(body.get("text", "") or "")
    else:
        body_text = str(body or "")

    # ---------------------------------------------------------
    # Evidence metadata
    # ---------------------------------------------------------

    source_file = str(
        evidence_info.get("source_file", "") or ""
    )

    filename = str(
        evidence_info.get("filename", "") or ""
    )

    sha256 = str(
        evidence_info.get("sha256", "") or ""
    )

    # ---------------------------------------------------------
    # Calculate actual MD5
    # ---------------------------------------------------------

    md5_hash = calculate_md5(
        source_file=source_file,
        fallback_sha256=sha256,
    )

    # ---------------------------------------------------------
    # Existing cases table
    #
    # case_id
    # md5_hash
    # filename
    # sender_raw
    # sender_clean
    # recipient_raw
    # subject
    # date_sent
    # origin_ip
    # has_spf
    # dkim_status
    # dmarc_policy
    # threat_score
    # threat_level
    # body_plain
    # headers_json
    # ingested_at -> MySQL DEFAULT CURRENT_TIMESTAMP
    # ---------------------------------------------------------

    query = """
        INSERT INTO cases (
            case_id,
            md5_hash,
            filename,
            sender_raw,
            sender_clean,
            recipient_raw,
            subject,
            date_sent,
            origin_ip,
            has_spf,
            dkim_status,
            dmarc_policy,
            threat_score,
            threat_level,
            body_plain,
            headers_json
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        )
    """

    params = (
        case_id,
        md5_hash,
        filename,
        sender,
        sender,
        recipient,
        subject,
        date_sent,
        None,  # origin_ip
        None,  # has_spf
        None,  # dkim_status
        None,  # dmarc_policy
        int(threat_score),
        threat_level,
        body_text,
        json.dumps(
            headers,
            ensure_ascii=False,
        ),
    )

    return execute_query(
        query,
        params,
    )


def get_case(case_id: str):
    """
    Retrieve one forensic case by case_id.
    """

    query = """
        SELECT *
        FROM cases
        WHERE case_id = %s
    """

    return fetch_one(
        query,
        (case_id,),
    )


def case_exists(case_id: str) -> bool:
    """
    Check whether a case already exists.
    """

    query = """
        SELECT case_id
        FROM cases
        WHERE case_id = %s
        LIMIT 1
    """

    result = fetch_one(
        query,
        (case_id,),
    )

    return result is not None


def get_case_count() -> int:
    """
    Return the total number of cases in MySQL.
    """

    query = """
        SELECT COUNT(*) AS total
        FROM cases
    """

    result = fetch_one(query)

    return int(result["total"])


def delete_case(case_id: str):
    """
    Delete a case by case_id.

    Use carefully because this modifies the database.
    """

    query = """
        DELETE FROM cases
        WHERE case_id = %s
    """

    return execute_query(
        query,
        (case_id,),
    )


if __name__ == "__main__":
    print("CASES REPOSITORY: IMPORT PASS")