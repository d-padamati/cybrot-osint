import dns.resolver
import secrets
import re


MAX_HOSTS = 5
DNS_TIMEOUT = 1.0
DNS_LIFETIME = 2.0


def _is_valid_subdomain(hostname, domain):
    hostname = hostname.lower().rstrip(".")
    domain = domain.lower().rstrip(".")

    if hostname == domain:
        return False

    if not hostname.endswith("." + domain):
        return False

    labels = hostname.split(".")

    return all(
        re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            label
        )
        for label in labels
    )


def _query_records(hostname, record_type, resolver):
    try:
        answers = resolver.resolve(
            hostname,
            record_type,
            lifetime=DNS_LIFETIME
        )

        records = []

        for answer in answers:
            records.append({
                "type": record_type,
                "ttl": answers.rrset.ttl,
                "data": answer.to_text().rstrip(".")
            })

        return records, None

    except dns.resolver.NXDOMAIN:
        return [], None

    except dns.resolver.NoAnswer:
        return [], None

    except Exception as error:
        return [], str(error)[:200]


def resolve_subdomain(hostname):
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME

    result = {
        "hostname": hostname,
        "dns_status": "unresolved",
        "ip_addresses": [],
        "A": [],
        "AAAA": [],
        "CNAME": {
            "status": "not_found",
            "records": [],
            "targets": [],
            "error": None
        },
        "errors": []
    }

    for record_type in ("A", "AAAA", "CNAME"):
        records, error = _query_records(
            hostname,
            record_type,
            resolver
        )

        if record_type == "A":
            result["A"] = [
                record["data"] for record in records
            ]

        elif record_type == "AAAA":
            result["AAAA"] = [
                record["data"] for record in records
            ]

        else:
            result["CNAME"]["records"] = records
            result["CNAME"]["targets"] = sorted({
                record["data"] for record in records
            })

            if result["CNAME"]["targets"]:
                result["CNAME"]["status"] = "found"

            if error:
                result["CNAME"]["status"] = "lookup_failed"
                result["CNAME"]["error"] = error

        if error:
            result["errors"].append({
                "record_type": record_type,
                "error": error
            })

    result["ip_addresses"] = sorted(
        set(result["A"] + result["AAAA"])
    )

    if result["ip_addresses"] or result["CNAME"]["status"] == "found":
        result["dns_status"] = "resolved"

    return result


def detect_wildcard_dns(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME

    hostname = f"cybrot-{secrets.token_hex(8)}.{domain}"

    records, error = _query_records(
        hostname,
        "A",
        resolver
    )

    return {
        "detected": bool(records),
        "status": (
            "possible_wildcard" if records
            else "lookup_failed" if error
            else "not_detected"
        ),
        "test_hostname": hostname,
        "records": records,
        "error": error,
        "note": "Indicator only; manual verification is required."
    }


def enrich_subdomains(domain, subdomains):
    selected = sorted({
        hostname.lower().rstrip(".")
        for hostname in subdomains
        if _is_valid_subdomain(hostname, domain)
    })[:MAX_HOSTS]

    assets = [
        resolve_subdomain(hostname)
        for hostname in selected
    ]

    resolved_count = sum(
        asset["dns_status"] == "resolved"
        for asset in assets
    )

    return {
        "assets": assets,
        "total_checked": len(assets),
        "total_skipped": max(0, len(subdomains) - len(assets)),
        "total_resolved": resolved_count,
        "total_unresolved": len(assets) - resolved_count,
        "cname_intelligence": {
            "total_with_cname": sum(
                asset["CNAME"]["status"] == "found"
                for asset in assets
            )
        },
        "wildcard_dns": detect_wildcard_dns(domain)
    }
