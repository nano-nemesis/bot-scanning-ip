import ipaddress
import logging

import aiohttp

RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_NETWORK_INFO_URL = "https://stat.ripe.net/data/network-info/data.json"
logger = logging.getLogger(__name__)


async def fetch_prefixes(as_number: str) -> list[str]:
    """Fetch all announced IPv4 prefixes for an AS from RIPE Stat."""
    params = {"resource": as_number}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            RIPE_URL, params=params, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()

    raw = data.get("data", {}).get("prefixes", [])
    prefixes = []
    for entry in raw:
        prefix = entry.get("prefix", "")
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if net.version == 4:
                prefixes.append(str(net))
        except ValueError:
            logger.warning("Skipping invalid prefix: %s", prefix)

    logger.info("Fetched %d IPv4 prefixes for %s", len(prefixes), as_number)
    return prefixes


async def lookup_ip_prefix(ip: str) -> str:
    """Return the announced prefix that contains this IP, or '-' if not found."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                RIPE_NETWORK_INFO_URL,
                params={"resource": ip},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return "-"
                data = await resp.json()
        prefix = data.get("data", {}).get("prefix")
        return prefix if prefix else "-"
    except Exception as exc:
        logger.warning("RIPE prefix lookup failed for %s: %s", ip, exc)
        return "-"


def count_total_ips(prefixes: list[str]) -> int:
    return sum(
        ipaddress.ip_network(p, strict=False).num_addresses for p in prefixes
    )
