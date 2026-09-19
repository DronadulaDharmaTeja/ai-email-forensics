from pathlib import Path
from mcp_server.server import (
    health_check,
    parse_email,
    analyze_headers,
    analyze_url,
    calculate_risk,
)

EMAIL = Path(r"datasets\enron\sample_emails\email_0009.eml")

print("=" * 60)
print("EMAIL FORENSICS MCP INTEGRATION TEST")
print("=" * 60)

health = health_check()
assert health["status"] == "ok"
print("1. health_check   : PASS")

parsed = parse_email(str(EMAIL))
assert isinstance(parsed, dict)
print("2. parse_email    : PASS")

headers = analyze_headers(str(EMAIL))
assert isinstance(headers, dict)
print("3. analyze_headers: PASS")

body = parsed.get("email", {}).get("body", {}).get("text", "")

import re
urls = re.findall(
    r"https?://[^\s<>\")]+",
    str(body),
    re.IGNORECASE,
)

url_results = []
for url in urls:
    result = analyze_url(url.rstrip(".,;:!?"))
    assert result.get("executed") is False
    url_results.append(result)

print("4. analyze_url    : PASS")
print("   URLs analyzed  :", len(url_results))

risk = calculate_risk(parsed)
assert isinstance(risk, dict)
print("5. calculate_risk : PASS")
print("   Score          :", risk.get("score"))
print("   Strength       :", risk.get("strength"))
print("   URL count      :", risk.get("derived_url_count"))

print("=" * 60)
print("MCP INTEGRATION TEST: PASS")
print("=" * 60)
