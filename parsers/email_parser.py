import hashlib
from email import policy
from email.parser import BytesParser
from pathlib import Path


def sha256_file(file_path):
    h = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def parse_eml(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(str(path))

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported")

    with open(path, "rb") as f:
        message = BytesParser(
            policy=policy.default
        ).parse(f)

    headers = {}

    for key, value in message.items():
        value = str(value)

        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(value)
            else:
                headers[key] = [headers[key], value]
        else:
            headers[key] = value

    body = ""

    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        if part.get_content_type() == "text/plain":
            try:
                body += part.get_content()
            except Exception:
                pass

    return {
        "schema_version": "1.0",
        "evidence": {
            "source_file": str(path),
            "filename": path.name,
            "sha256": sha256_file(path),
            "read_only": True,
            "source_type": "EML"
        },
        "email": {
            "from": str(message.get("From", "")),
            "to": str(message.get("To", "")),
            "subject": str(message.get("Subject", "")),
            "date": str(message.get("Date", "")),
            "message_id": str(message.get("Message-ID", "")),
            "reply_to": str(message.get("Reply-To", "")),
            "body": {
                "text": body.strip(),
                "length": len(body.strip())
            }
        },
        "headers": headers
    }

    
def save_forensic_json(evidence, output_path):
    import json
    from pathlib import Path

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as f:
        json.dump(
            evidence,
            f,
            indent=2,
            ensure_ascii=False
        )

    return str(output)
