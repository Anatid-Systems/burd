"""Export IOCs and Custom IOA rule groups from a CrowdStrike Falcon CID."""

from __future__ import annotations

from typing import TYPE_CHECKING

from falconpy import IOC, CustomIOA

from burd._pagination import paginate

if TYPE_CHECKING:
    from burd.auth import Cid


def export_iocs(cid: Cid):
    """Fetch all custom IOCs from a Falcon CID.

    Returns a list of indicator dicts.
    """
    falcon = IOC(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    print(f"[*] Fetching custom IOCs from {cid.name}...")
    indicators = paginate(falcon.indicator_combined)
    print(f"[+] Retrieved {len(indicators)} IOCs")
    return indicators


def export_custom_ioas(cid: Cid):
    """Fetch all Custom IOA rule groups (with embedded rules) from a Falcon CID.

    Returns a list of rule group dicts.
    """
    falcon = CustomIOA(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    # Step 1: get all rule group IDs
    print(f"[*] Fetching Custom IOA rule groups from {cid.name}...")
    group_ids = paginate(falcon.query_rule_groups, limit=100)
    print(f"[+] Found {len(group_ids)} rule groups")

    # Step 2: fetch full detail (includes embedded rules), chunked to avoid URL length limits
    print("[*] Fetching rule group details...")
    all_groups = []
    chunk_size = 20
    for i in range(0, len(group_ids), chunk_size):
        chunk = group_ids[i : i + chunk_size]
        response = falcon.get_rule_groups(ids=chunk)
        if response["status_code"] != 200:
            raise RuntimeError(f"API error: {response['body']}")
        all_groups.extend(response["body"].get("resources", []))

    print(f"[+] Retrieved {len(all_groups)} rule groups with embedded rules")
    return all_groups
