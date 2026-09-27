import asyncio
import httpx

URL = "http://127.0.0.1:8000/health"

async def test_request(client, number):
    try:
        response = await client.get(URL, timeout=10)
        print(f"Request {number}: {response.status_code} | {response.text}")
    except Exception as e:
        print(f"Request {number}: ERROR | {type(e).__name__}: {e}")

async def main():
    print("=" * 55)
    print("AI EMAIL FORENSICS - PARALLEL HEALTH TEST")
    print("=" * 55)

    async with httpx.AsyncClient() as client:
        await asyncio.gather(
            test_request(client, 1),
            test_request(client, 2),
            test_request(client, 3),
            test_request(client, 4),
            test_request(client, 5)
        )

asyncio.run(main())
