"""Import IOCs and Custom IOA rule groups into a CrowdStrike Falcon CID."""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING

from falconpy import IOC, CustomIOA

from burd._fields import (
    IOC_READONLY_FIELDS,
    RULE_GROUP_READONLY_FIELDS,
    RULE_READONLY_FIELDS,
    strip_fields,
)
from burd._pagination import paginate

if TYPE_CHECKING:
    from burd.auth import Cid


def import_iocs(cid: Cid, iocs, *, dry_run=False):
    """Import IOCs into a Falcon CID, skipping duplicates.

    Args:
        cid: Target CID credentials.
        iocs: List of indicator dicts (as returned by export_iocs).
        dry_run: If True, report what would be created without making changes.

    Returns:
        Dict with keys: created, skipped, errors.
    """
    if not iocs:
        print("[*] No IOCs to import")
        return {"created": 0, "skipped": 0, "errors": 0}

    falcon = IOC(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    # Fetch existing IOCs for dedup — (type, value) is the natural key
    print(f"[*] Fetching existing IOCs from {cid.name} for dedup check...")
    existing = set()
    for r in paginate(falcon.indicator_combined):
        existing.add((r.get("type"), r.get("value")))

    print(f"[+] {len(existing)} IOCs already exist in {cid.name}")

    to_create = []
    skipped = 0
    for ind in iocs:
        if (ind.get("type"), ind.get("value")) in existing:
            skipped += 1
            continue
        to_create.append(strip_fields(ind, IOC_READONLY_FIELDS))

    print(f"[*] {len(to_create)} to create, {skipped} skipped (already exist)")

    if dry_run:
        print("[DRY RUN] Would create the above IOCs. Exiting.")
        return {"created": 0, "skipped": skipped, "errors": 0}

    # Create in chunks (API accepts up to 2000, we use 200 conservatively)
    chunk_size = 200
    created = 0
    errors = 0
    for i in range(0, len(to_create), chunk_size):
        chunk = to_create[i : i + chunk_size]
        response = falcon.indicator_create_v1(
            body={"comment": "Imported via burd", "indicators": chunk}
        )
        if response["status_code"] in (200, 201):
            count = len(response["body"].get("resources", []))
            created += count
            print(f"  [+] Chunk {i // chunk_size + 1}: created {count}")
        else:
            errors += 1
            print(
                f"  [-] Chunk {i // chunk_size + 1} failed: {response['body']}",
                file=sys.stderr,
            )

        time.sleep(0.5)

    print(f"[+] IOC import complete: {created} created, {errors} chunk errors")
    return {"created": created, "skipped": skipped, "errors": errors}


def import_custom_ioas(cid: Cid, rule_groups, *, dry_run=False):
    """Import Custom IOA rule groups (with rules) into a Falcon CID, skipping duplicates.

    All groups and rules are created **disabled** so an operator can review before enabling.

    Args:
        cid: Target CID credentials.
        rule_groups: List of rule group dicts (as returned by export_custom_ioas).
        dry_run: If True, report what would be created without making changes.

    Returns:
        Dict with keys: created_groups, skipped_groups, error_groups, created_rules.
    """
    if not rule_groups:
        print("[*] No Custom IOA rule groups to import")
        return {
            "created_groups": 0,
            "skipped_groups": 0,
            "error_groups": 0,
            "created_rules": 0,
        }

    falcon = CustomIOA(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    # Fetch existing group names for dedup
    print(f"[*] Fetching existing IOA rule groups from {cid.name} for dedup check...")
    existing_names = set()
    offset = 0
    limit = 100
    while True:
        response = falcon.query_rule_groups(offset=offset, limit=limit)
        if response["status_code"] != 200:
            raise RuntimeError(f"Failed to query rule groups: {response['body']}")
        ids = response["body"].get("resources", [])
        if ids:
            detail = falcon.get_rule_groups(ids=ids)
            if detail["status_code"] == 200:
                for g in detail["body"].get("resources", []):
                    existing_names.add(g.get("name"))
        meta = response["body"].get("meta", {}).get("pagination", {})
        offset += len(ids)
        if offset >= meta.get("total", 0) or not ids:
            break

    print(f"[+] {len(existing_names)} rule groups already exist in {cid.name}")

    created_groups = 0
    skipped_groups = 0
    created_rules = 0
    error_groups = 0

    for group in rule_groups:
        group_name = group.get("name")

        if group_name in existing_names:
            print(f"  [~] Skipping group '{group_name}' (already exists)")
            skipped_groups += 1
            continue

        if dry_run:
            rule_count = len(group.get("rules", []))
            print(
                f"  [DRY RUN] Would create group '{group_name}' with {rule_count} rules"
            )
            continue

        # Create the rule group (rules are added separately)
        group_payload = strip_fields(group, RULE_GROUP_READONLY_FIELDS)
        rules = group_payload.pop("rules", [])

        response = falcon.create_rule_group(
            name=group_payload.get("name"),
            description=group_payload.get("description", ""),
            comment="Imported via burd",
            ruletype_id=group_payload.get("ruletype_id"),
            platform=group_payload.get("platform"),
            enabled=False,
        )

        if response["status_code"] not in (200, 201):
            print(
                f"  [-] Failed to create group '{group_name}': {response['body']}",
                file=sys.stderr,
            )
            error_groups += 1
            continue

        new_group_id = response["body"]["resources"][0]["id"]
        created_groups += 1
        print(f"  [+] Created group '{group_name}' -> {new_group_id}")

        # Create rules within the group
        for rule in rules:
            rule_payload = strip_fields(rule, RULE_READONLY_FIELDS)

            rule_response = falcon.create_rule(
                body={
                    "comment": "Imported via burd",
                    "rulegroup_id": new_group_id,
                    "name": rule_payload.get("name"),
                    "description": rule_payload.get("description", ""),
                    "pattern_severity": rule_payload.get("pattern_severity"),
                    "disposition_id": rule_payload.get("disposition_id"),
                    "field_values": rule_payload.get("field_values", []),
                    "ruletype_id": rule_payload.get("ruletype_id"),
                    "enabled": False,
                }
            )

            if rule_response["status_code"] in (200, 201):
                created_rules += 1
            else:
                print(
                    f"    [-] Failed to create rule '{rule.get('name')}' "
                    f"in group '{group_name}': {rule_response['body']}",
                    file=sys.stderr,
                )

            time.sleep(0.25)

        time.sleep(0.5)

    if dry_run:
        print("[DRY RUN] No changes made.")
        return {
            "created_groups": 0,
            "skipped_groups": skipped_groups,
            "error_groups": 0,
            "created_rules": 0,
        }

    print(
        f"[+] Custom IOA import complete: "
        f"{created_groups} groups created, {skipped_groups} skipped, "
        f"{error_groups} errors, {created_rules} rules created"
    )
    return {
        "created_groups": created_groups,
        "skipped_groups": skipped_groups,
        "error_groups": error_groups,
        "created_rules": created_rules,
    }
