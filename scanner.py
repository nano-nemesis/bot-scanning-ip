import asyncio
import json
import logging
import random
from dataclasses import dataclass, field

import aiohttp

from config import config

logger = logging.getLogger(__name__)

ABUSEIPDB_CHECK_BLOCK = "https://api.abuseipdb.com/api/v2/check-block"
ABUSEIPDB_CHECK_IP = "https://api.abuseipdb.com/api/v2/check"

CATEGORY_NAMES: dict[int, str] = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}

VOIDIP_TAGS_POOL = [
    "proxy", "spam", "bot", "scanner", "brute-force",
    "malware", "phishing", "vpn", "tor-exit",
]


@dataclass
class PrefixScanResult:
    prefix: str
    success: bool
    error: str | None
    total_reports: int
    reported_ips: int
    max_score: int
    ip_list: list[dict] = field(default_factory=list)
    raw_json: str = ""


async def _check_block(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    prefix: str,
) -> PrefixScanResult:
    headers = {
        "Key": config.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {"network": prefix, "maxAgeInDays": str(config.max_age_days)}

    async with semaphore:
        for attempt in range(3):
            try:
                async with session.get(
                    ABUSEIPDB_CHECK_BLOCK,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 429:
                        wait = (2 ** attempt) * 10
                        logger.warning("Rate limited on %s, waiting %ds", prefix, wait)
                        await asyncio.sleep(wait)
                        continue
                    if resp.status != 200:
                        text = await resp.text()
                        logger.error("AbuseIPDB error %d for %s: %s", resp.status, prefix, text)
                        return PrefixScanResult(
                            prefix=prefix, success=False,
                            error=f"HTTP {resp.status}", total_reports=0,
                            reported_ips=0, max_score=0,
                        )

                    remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
                    data = await resp.json()
                    reported = data.get("data", {}).get("reportedAddress", [])

                    ip_list = []
                    max_score = 0
                    total_reports = 0
                    for entry in reported:
                        score = entry.get("abuseConfidenceScore", 0)
                        reports = entry.get("numReports", 0)
                        max_score = max(max_score, score)
                        total_reports += reports
                        ip_list.append({
                            "ip_address": entry.get("ipAddress", ""),
                            "abuse_score": score,
                            "num_reports": reports,
                            "last_reported": entry.get("mostRecentReport"),
                            "country_code": entry.get("countryCode"),
                            "categories": [],
                            "voidip_score": 0.0,
                            "voidip_tags": [],
                        })

                    if remaining < 50:
                        logger.warning("Rate limit low (%d remaining), skipping second pass", remaining)
                    else:
                        ip_list = await _second_pass_categories(session, semaphore, ip_list, remaining)

                    return PrefixScanResult(
                        prefix=prefix,
                        success=True,
                        error=None,
                        total_reports=total_reports,
                        reported_ips=len(ip_list),
                        max_score=max_score,
                        ip_list=ip_list,
                        raw_json=json.dumps(data),
                    )

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.warning("Network error on %s attempt %d: %s", prefix, attempt, exc)
                if attempt == 2:
                    return PrefixScanResult(
                        prefix=prefix, success=False, error=str(exc),
                        total_reports=0, reported_ips=0, max_score=0,
                    )
                await asyncio.sleep((2 ** attempt) * 5)

    return PrefixScanResult(
        prefix=prefix, success=False, error="Max retries exceeded",
        total_reports=0, reported_ips=0, max_score=0,
    )


async def _second_pass_categories(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    ip_list: list[dict],
    remaining: int,
) -> list[dict]:
    """Fetch category data for high-score IPs (score >= 50)."""
    high_score = [ip for ip in ip_list if ip["abuse_score"] >= 50]
    if not high_score or remaining - len(high_score) < 50:
        return ip_list

    headers = {"Key": config.abuseipdb_api_key, "Accept": "application/json"}

    async def fetch_categories(ip_dict: dict) -> None:
        params = {"ipAddress": ip_dict["ip_address"], "maxAgeInDays": str(config.max_age_days)}
        try:
            async with semaphore:
                async with session.get(
                    ABUSEIPDB_CHECK_IP, headers=headers, params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        cats = data.get("data", {}).get("reports", [])
                        all_cats: list[int] = []
                        for r in cats:
                            all_cats.extend(r.get("categories", []))
                        ip_dict["categories"] = list(set(all_cats))
        except Exception as exc:
            logger.debug("Category fetch failed for %s: %s", ip_dict["ip_address"], exc)

    await asyncio.gather(*[fetch_categories(ip) for ip in high_score])
    return ip_list


async def check_ip_voidip_mock(ip: str) -> dict:
    """Deterministic mock VoidIP response — same IP always gives same result."""
    rng = random.Random(hash(ip) & 0xFFFFFFFF)
    listed = rng.random() < 0.15
    score = round(rng.uniform(60, 95), 1) if listed else round(rng.uniform(0, 20), 1)
    tags = rng.sample(VOIDIP_TAGS_POOL, k=rng.randint(1, 3)) if listed else []
    return {
        "ip": ip,
        "score": score,
        "listed": listed,
        "tags": tags,
        "reports": rng.randint(1, 50) if listed else 0,
        "source": "voidip_mock",
    }


async def validate_abuseipdb_token() -> bool:
    """Quick validation: check a well-known IP to verify the API key works."""
    headers = {"Key": config.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": "8.8.8.8", "maxAgeInDays": "1"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                ABUSEIPDB_CHECK_IP, headers=headers, params=params,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
    except Exception:
        return False


async def scan_all_prefixes(prefixes: list[str]) -> list[PrefixScanResult]:
    semaphore = asyncio.Semaphore(config.scan_concurrency)
    connector = aiohttp.TCPConnector(limit=10)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check_block(session, semaphore, prefix) for prefix in prefixes]
        results = await asyncio.gather(*tasks)

    # Enrich reported IPs with VoidIP mock data
    for result in results:
        if result.success and result.ip_list:
            voidip_tasks = [check_ip_voidip_mock(ip["ip_address"]) for ip in result.ip_list]
            voidip_data = await asyncio.gather(*voidip_tasks)
            for ip_dict, void_data in zip(result.ip_list, voidip_data):
                ip_dict["voidip_score"] = void_data["score"]
                ip_dict["voidip_tags"] = void_data["tags"]

    return list(results)


def aggregate_categories(results: list[PrefixScanResult]) -> dict[int, tuple[str, int]]:
    """Returns {category_id: (category_name, ip_count)}."""
    counts: dict[int, int] = {}
    for result in results:
        for ip in result.ip_list:
            for cat_id in ip.get("categories", []):
                counts[cat_id] = counts.get(cat_id, 0) + 1

    return {
        cat_id: (CATEGORY_NAMES.get(cat_id, f"Category {cat_id}"), count)
        for cat_id, count in counts.items()
    }
