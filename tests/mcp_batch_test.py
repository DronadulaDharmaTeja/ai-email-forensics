from pathlib import Path
from mcp_server.server import parse_email, analyze_headers, analyze_url, calculate_risk

ROOT = Path(r"datasets\enron\sample_emails")
EMAIL_IDS = ["0009", "0005", "0020", "0021", "0075"]

print("=" * 60)
print("MCP END-TO-END BATCH TEST")
print("=" * 60)

for email_id in EMAIL_IDS:
    path = ROOT / f"email_{email_id}.eml"

    try:
        parsed = parse_email(str(path))
        headers = analyze_headers(str(path))
        risk = calculate_risk(parsed)

        print(f"\nEMAIL {email_id}")
        print("-" * 40)
        print("Parse       : PASS")
        print("Headers     : PASS")
        print("Risk        : PASS")
        print("Score       :", risk.get("score"))
        print("Strength    :", risk.get("strength"))
        print("URL count   :", risk.get("derived_url_count"))
        print("Indicators  :", risk.get("indicators"))

    except Exception as e:
        print(f"\nEMAIL {email_id}")
        print("-" * 40)
        print("STATUS      : FAIL")
        print("ERROR       :", type(e).__name__, str(e))

print("\n" + "=" * 60)
print("BATCH TEST COMPLETE")
print("=" * 60)
