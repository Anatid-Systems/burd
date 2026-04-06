"""Find and remove duplicate host/sensor records from a CrowdStrike Falcon CID."""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING

from falconpy import Hosts

if TYPE_CHECKING:
    from burd.auth import Cid

# Fields retrieved for each host record.
_HOST_FIELDS = [
    "device_id",
    "hostname",
    "mac_address",
    "platform_name",
    "os_version",
    "first_seen",
    "last_seen",
]


def _fetch_all_hosts(falcon):
    """Scroll through all host IDs, then batch-fetch details."""
    # Step 1: collect all device IDs via scroll API
    device_ids = []
    offset = None
    while True:
        kwargs = {"limit": 5000}
        if offset is not None:
            kwargs["offset"] = offset
        response = falcon.query_devices_by_filter_scroll(**kwargs)
        if response["status_code"] != 200:
            raise RuntimeError(
                f"API error {response['status_code']}: {response['body']}"
            )
        batch = response["body"].get("resources", [])
        device_ids.extend(batch)

        meta = response["body"].get("meta", {})
        offset = meta.get("offset")
        total = meta.get("pagination", {}).get("total", 0)

        if not batch or len(device_ids) >= total:
            break

    print(f"[+] Found {len(device_ids)} device IDs")

    # Step 2: fetch details in chunks
    hosts = []
    chunk_size = 500
    for i in range(0, len(device_ids), chunk_size):
        chunk = device_ids[i : i + chunk_size]
        response = falcon.get_device_details(ids=chunk)
        if response["status_code"] != 200:
            raise RuntimeError(
                f"API error {response['status_code']}: {response['body']}"
            )
        hosts.extend(response["body"].get("resources", []))

    return hosts


def find_duplicate_hosts(cid: Cid):
    """Identify duplicate hosts in a Falcon CID.

    Hosts are grouped by (hostname, mac_address). Within each group the host
    with the most recent ``last_seen`` timestamp is kept; the rest are returned
    as duplicates.

    Returns:
        Tuple of (duplicates, kept) where each is a list of dicts containing
        the fields defined in ``_HOST_FIELDS``.
    """
    falcon = Hosts(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    print(f"[*] Fetching hosts from {cid.name}...")
    hosts = _fetch_all_hosts(falcon)
    print(f"[+] Retrieved {len(hosts)} host records")

    # Group by (hostname, mac_address)
    groups: dict[tuple, list[dict]] = {}
    for host in hosts:
        key = (
            (host.get("hostname") or "").lower(),
            (host.get("mac_address") or "").lower(),
        )
        record = {f: host.get(f) for f in _HOST_FIELDS}
        groups.setdefault(key, []).append(record)

    duplicates = []
    kept = []
    for key, members in groups.items():
        if len(members) < 2:
            continue
        # Sort by last_seen descending — keep the newest
        members.sort(key=lambda h: h.get("last_seen") or "", reverse=True)
        kept.append(members[0])
        duplicates.extend(members[1:])

    print(
        f"[*] {len(groups)} unique (hostname, mac_address) groups, "
        f"{len(duplicates)} duplicates identified across "
        f"{len(kept)} groups with duplicates"
    )

    return duplicates, kept


def hide_duplicate_hosts(cid: Cid, duplicates, *, dry_run=False):
    """Hide (soft-delete) duplicate hosts from a Falcon CID.

    Args:
        cid: Target CID credentials.
        duplicates: List of host dicts as returned by ``find_duplicate_hosts``.
        dry_run: If True, report what would be hidden without making changes.

    Returns:
        Dict with keys: hidden, errors.
    """
    if not duplicates:
        print("[*] No duplicates to hide")
        return {"hidden": 0, "errors": 0}

    ids = [d["device_id"] for d in duplicates]

    if dry_run:
        print(f"[DRY RUN] Would hide {len(ids)} duplicate hosts:")
        for d in duplicates:
            print(
                f"  {d['device_id']}  {d.get('hostname')}  "
                f"mac={d.get('mac_address')}  last_seen={d.get('last_seen')}"
            )
        return {"hidden": 0, "errors": 0}

    falcon = Hosts(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    hidden = 0
    errors = 0
    chunk_size = 100
    for i in range(0, len(ids), chunk_size):
        chunk = ids[i : i + chunk_size]
        response = falcon.perform_action(action_name="hide_host", ids=chunk)
        if response["status_code"] in (200, 202):
            hidden += len(chunk)
            print(f"  [+] Chunk {i // chunk_size + 1}: hid {len(chunk)} hosts")
        else:
            errors += 1
            print(
                f"  [-] Chunk {i // chunk_size + 1} failed: {response['body']}",
                file=sys.stderr,
            )
        time.sleep(0.5)

    print(f"[+] Hide complete: {hidden} hidden, {errors} chunk errors")
    return {"hidden": hidden, "errors": errors}
