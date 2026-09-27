import asyncio
import time
import httpx

URL = "http://127.0.0.1:8000/cases/email_0009/investigate?rounds=1"

CONCURRENT_REQUESTS = 2


async def send_request(client, request_number):
    start = time.perf_counter()

    try:
        response = await client.post(URL, timeout=300)

        elapsed = time.perf_counter() - start

        print(
            f"Request {request_number}: "
            f"Status={response.status_code} "
            f"Time={elapsed:.2f}s"
        )

        return response.status_code

    except Exception as e:
        elapsed = time.perf_counter() - start

        print(
            f"Request {request_number}: "
            f"FAILED "
            f"Time={elapsed:.2f}s "
            f"Error={e}"
        )

        return None


async def main():
    print("=" * 60)
    print("AI EMAIL FORENSICS - PARALLEL API TEST")
    print("=" * 60)
    print(f"Concurrent requests: {CONCURRENT_REQUESTS}")
    print(f"URL: {URL}")
    print()

    async with httpx.AsyncClient() as client:

        start = time.perf_counter()

        tasks = [
            send_request(client, i + 1)
            for i in range(CONCURRENT_REQUESTS)
        ]

        results = await asyncio.gather(*tasks)

        total_time = time.perf_counter() - start

    successful = sum(
        1 for status in results
        if status == 200
    )

    failed = CONCURRENT_REQUESTS - successful

    print()
    print("=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"Total requests : {CONCURRENT_REQUESTS}")
    print(f"Successful     : {successful}")
    print(f"Failed         : {failed}")
    print(f"Total time     : {total_time:.2f}s")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())