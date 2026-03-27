"""
VirusTotal integration module.
Queries the VirusTotal v3 API for IP/domain reputation data.
"""

import httpx
import os
from models import VTResult
from dotenv import load_dotenv
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def check_virustotal(target: str) -> VTResult:
    """
    Check an IP address or domain against VirusTotal.
    Returns aggregated threat intelligence data.
    """
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY environment variable is not set")

    headers = {"x-apikey": VT_API_KEY}

    # Determine endpoint based on whether target is IP or domain
    if _is_ip(target):
        url = f"{VT_BASE_URL}/ip_addresses/{target}"
    else:
        url = f"{VT_BASE_URL}/domains/{target}"

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 404:
        # Target not in VirusTotal database — return clean baseline
        return VTResult(target=target, permalink=f"https://www.virustotal.com/gui/ip-address/{target}")

    if response.status_code == 401:
        raise RuntimeError("Invalid VirusTotal API key")

    if response.status_code != 200:
        raise RuntimeError(f"VirusTotal API error: {response.status_code} {response.text[:200]}")

    data = response.json().get("data", {})
    attrs = data.get("attributes", {})

    last_analysis = attrs.get("last_analysis_stats", {})
    categories_raw = attrs.get("categories", {})

    # Flatten category values from different engine sources
    categories = list(set(categories_raw.values())) if isinstance(categories_raw, dict) else []

    permalink = f"https://www.virustotal.com/gui/ip-address/{target}"
    if not _is_ip(target):
        permalink = f"https://www.virustotal.com/gui/domain/{target}"

    return VTResult(
        target=target,
        malicious_count=last_analysis.get("malicious", 0),
        suspicious_count=last_analysis.get("suspicious", 0),
        harmless_count=last_analysis.get("harmless", 0),
        undetected_count=last_analysis.get("undetected", 0),
        community_score=attrs.get("reputation", 0),
        categories=categories[:10],  # cap to avoid bloat
        last_analysis_date=str(attrs.get("last_analysis_date", "")),
        permalink=permalink,
    )


def _is_ip(target: str) -> bool:
    """Simple check to differentiate IP addresses from domain names."""
    parts = target.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
