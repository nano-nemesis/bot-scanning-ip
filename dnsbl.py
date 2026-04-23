import asyncio
import ipaddress
import logging
import socket

logger = logging.getLogger(__name__)

DNSBL_ZONES: list[tuple[str, str]] = [
    ("sbl.spamhaus.org",       "Spamhaus SBL"),
    ("xbl.spamhaus.org",       "Spamhaus XBL"),
    ("pbl.spamhaus.org",       "Spamhaus PBL"),
    ("bl.spamcop.net",         "SpamCop"),
    ("dnsbl.sorbs.net",        "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl-1.uceprotect.net", "UCEProtect L1"),
    ("cbl.abuseat.org",        "CBL Abuseat"),
]

_LOOKUP_TIMEOUT = 5.0


def _reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


async def _is_listed(reversed_ip: str, zone: str) -> bool:
    hostname = f"{reversed_ip}.{zone}"
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, hostname),
            timeout=_LOOKUP_TIMEOUT,
        )
        return True
    except (asyncio.TimeoutError, socket.gaierror, OSError):
        return False


async def check_dnsbl(ip: str) -> list[tuple[str, str, bool]]:
    """
    Check IP against all DNSBL zones concurrently.
    Returns list of (zone, label, is_listed).
    Raises ValueError for invalid or non-routable input.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"IP tidak valid: {ip!r}")

    if addr.version != 4:
        raise ValueError("DNSBL hanya mendukung IPv4")
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_unspecified:
        raise ValueError("IP private/reserved tidak dapat dicek di DNSBL")

    reversed_ip = _reverse_ipv4(str(addr))
    results = await asyncio.gather(
        *[_is_listed(reversed_ip, zone) for zone, _ in DNSBL_ZONES]
    )
    return [(zone, label, listed) for (zone, label), listed in zip(DNSBL_ZONES, results)]


def format_dnsbl_result(ip: str, results: list[tuple[str, str, bool]]) -> str:
    listed_count = sum(1 for _, _, listed in results)
    total = len(results)

    if listed_count == 0:
        verdict = "✅ Bersih dari semua blacklist"
    elif listed_count <= 2:
        verdict = "⚠️ Terdeteksi di beberapa blacklist"
    else:
        verdict = "🚨 Terdeteksi di banyak blacklist!"

    lines = [f"🔍 *DNSBL Check: `{ip}`*\n"]
    for _, label, listed in results:
        icon = "❌" if listed else "✅"
        status = "LISTED" if listed else "Clean"
        lines.append(f"{icon} `{label}` — {status}")

    lines.append(f"\n📊 Result  : *{listed_count}/{total}* blacklist")
    lines.append(f"Verdict   : {verdict}")
    return "\n".join(lines)
