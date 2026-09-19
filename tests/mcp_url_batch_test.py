from pathlib import Path
from mcp_server.server import parse_email, analyze_url

ROOT = Path(r"datasets\enron\sample_emails")
EMAIL_IDS = ["0009", "0005", "0020", "0021", "0075"]

print("=" * 60)
print("MCP URL ANALYSIS BATCH TEST")
print("=" * 60)

for email_id in EMAIL_IDS:
    path = ROOT / f"email_{email_id}.eml"

    try:
        parsed = parse_email(str(path))
        body = parsed.get("email", {}).get("body", {}).get("text", "")

        import re
        urls = re.findall(r"https?://[^\s<>\")]+", str(body), re.IGNORECASE)

        print(f"\nEMAIL {email_id}")
        print("-" * 40)
        print("URLS FOUND:", len(urls))

        for url in urls:
            result = analyze_url(url.rstrip(".,;:!?"))
            print("URL:", url)
            print("Executed:", result.get("executed"))
            print("Valid:", result.get("valid_url"))
            print("Indicators:", result.get("indicators"))

        if not urls:
            print("No URLs found")

    except Exception as e:
        print("STATUS: FAIL")
        print("ERROR:", type(e).__name__, str(e))

print("\n" + "=" * 60)
print("URL BATCH TEST COMPLETE")
print("=" * 60)
