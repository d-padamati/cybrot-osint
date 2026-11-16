import re
import json
import csv
import io
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from app.modules.dns_enrichment import enrich_subdomains


def validate_domain(domain):
    domain = domain.strip().lower().rstrip(".")

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


def fetch_url(url, timeout=25):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CYBROT-OSINT/0.2",
            "Accept": "application/json,text/plain,*/*"
        }
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(5_000_000).decode("utf-8", errors="replace")


def fetch_crtsh(domain):
    url = "https://crt.sh/?" + urllib.parse.urlencode({
        "q": f"%.{domain}",
        "output": "json"
    })

    data = json.loads(fetch_url(url))

    if not isinstance(data, list):
        raise ValueError("Unexpected crt.sh response")

    found = set()

    for record in data:
        for name in record.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")

            if name.endswith("." + domain):
                found.add(name)

    return found


def fetch_hackertarget(domain):
    url = "https://api.hackertarget.com/hostsearch/?" + urllib.parse.urlencode({
        "q": domain
    })

    response = fetch_url(url)
    found = set()

    if "error" in response.lower() or "api count limit" in response.lower():
        raise RuntimeError(response.strip()[:200])

    for row in csv.reader(io.StringIO(response)):
        if not row:
            continue

        hostname = row[0].strip().lower().rstrip(".")

        if hostname.endswith("." + domain):
            found.add(hostname)

    return found


def discover_subdomains(domain):
    domain = validate_domain(domain)

    sources = [
        ("crt.sh", fetch_crtsh),
        ("HackerTarget", fetch_hackertarget)
    ]

    all_subdomains = set()
    successful_sources = []
    errors = []

    for source_name, source_function in sources:
        try:
            result = source_function(domain)
            all_subdomains.update(result)
            successful_sources.append(source_name)

        except Exception as error:
            errors.append(f"{source_name}: {str(error)[:250]}")

        time.sleep(1)

    if not successful_sources:
        raise RuntimeError(
            "All subdomain sources failed. " + " | ".join(errors)
        )

    # DNS enrichment is performed separately from passive discovery.
    # A DNS enrichment failure must not discard discovered subdomains.
    try:
        enrichment = enrich_subdomains(domain, sorted(all_subdomains))
    except Exception as error:
        enrichment = {
            "assets": [],
            "total_checked": 0,
            "total_skipped": len(all_subdomains),
            "total_resolved": 0,
            "total_unresolved": 0,
            "cname_intelligence": {"total_with_cname": 0},
            "wildcard_dns": {
                "detected": False,
                "status": "lookup_failed",
                "test_hostname": None,
                "records": [],
                "error": str(error)[:200],
                "note": "Wildcard DNS could not be checked."
            }
        }

    return {
        "status": "success",
        "domain": domain,
        "total": len(all_subdomains),
        "subdomains": sorted(all_subdomains),
        "sources": successful_sources,
        "source_errors": errors,
        **enrichment,
        "collection_type": "passive_with_dns_queries",
        "checked_at": datetime.now(timezone.utc).isoformat()
    }
