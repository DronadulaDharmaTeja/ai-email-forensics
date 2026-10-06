import asyncio
import time
import httpx
from statistics import mean

BASE_URL = "http://127.0.0.1:8000"
CASE_ID = "email_0009"

TIMEOUT = 30.0


async def run_test(client, name, method, url):
    start = time.perf_counter()

    try:
        response = await client.request(
            method,
            url,
            timeout=TIMEOUT
        )

        elapsed = time.perf_counter() - start

        return {
            "agent": name,
            "status": response.status_code,
            "latency": elapsed,
            "success": response.status_code < 400,
            "error": None,
        }

    except Exception as e:
        elapsed = time.perf_counter() - start

        return {
            "agent": name,
            "status": None,
            "latency": elapsed,
            "success": False,
            "error": f"{type(e).__name__}: {e}",
        }


async def main():

    print("=" * 70)
    print("FORENSIMAIL - AI AGENT BENCHMARK")
    print("=" * 70)

    print(f"API  : {BASE_URL}")
    print(f"CASE : {CASE_ID}")
    print()

    async with httpx.AsyncClient() as client:

        tests = [

            (
                "Case Retrieval Agent",
                "GET",
                f"{BASE_URL}/cases/{CASE_ID}",
            ),

            (
                "Semantic Search Agent",
                "GET",
                f"{BASE_URL}/semantic-search?case_id={CASE_ID}",
            ),

            (
                "Investigation Agent",
                "POST",
                f"{BASE_URL}/cases/{CASE_ID}/investigate?rounds=1",
            ),

        ]

        results = []

        for name, method, url in tests:

            print(f"Running: {name}")

            result = await run_test(
                client,
                name,
                method,
                url
            )

            results.append(result)

            if result["success"]:
                print(
                    f"  PASS | "
                    f"HTTP {result['status']} | "
                    f"{result['latency']:.2f}s"
                )
            else:
                print(
                    f"  FAIL | "
                    f"{result['latency']:.2f}s | "
                    f"{result['error']}"
                )

            print()

    # -------------------------------------------------
    # SUMMARY
    # -------------------------------------------------

    print("=" * 70)
    print("BENCHMARK RESULTS")
    print("=" * 70)

    successful = sum(
        1 for r in results
        if r["success"]
    )

    failed = len(results) - successful

    latencies = [
        r["latency"]
        for r in results
    ]

    average_latency = mean(latencies)

    success_rate = (
        successful / len(results) * 100
        if results
        else 0
    )

    for result in results:

        status = "PASS" if result["success"] else "FAIL"

        print(
            f"{status:<6} "
            f"{result['agent']:<30} "
            f"{result['latency']:>8.2f}s"
        )

    print()
    print("-" * 70)

    print(f"Total tests      : {len(results)}")
    print(f"Successful       : {successful}")
    print(f"Failed           : {failed}")
    print(f"Success rate     : {success_rate:.2f}%")
    print(f"Average latency  : {average_latency:.2f}s")

    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())