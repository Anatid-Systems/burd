"""Correlate Falcon detections to Cases for a CrowdStrike Falcon CID.

Workflow:

* :func:`find_open_detections_by_host` returns open detections grouped by host.
* :func:`list_open_cases` returns existing non-closed cases for the dropdown.
* :func:`correlate_detections_to_cases` takes operator-supplied per-host
  assignments and either attaches alerts to an existing case or creates a new
  case (with the alerts attached as evidence).
"""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING

from falconpy import Alerts, CaseManagement

from burd._pagination import paginate

if TYPE_CHECKING:
    from burd.auth import Cid


# Alert states considered "open" for triage. Anything else (closed,
# true_positive, false_positive, ignored) is excluded from the find step.
_OPEN_ALERT_STATUSES = ("new", "in_progress", "reopened")

# Case states considered selectable in the dropdown.
_OPEN_CASE_FILTER = "status:!'closed'"

# Falcon enforces a per-case total cap on attached alerts. Exceeding it
# yields "no more than 100 alerts may be added to a case".
_MAX_ALERTS_PER_CASE = 100

# Per-request safety cap for add_case_alert_evidence / create_case evidence.
# Stays strictly under the per-case cap so a single request never overshoots
# even on an empty case.
_REQUEST_CHUNK = 99

# Default severity for auto-created cases. Falcon requires an integer in
# [1, 100] on create_case; leaving it unset triggers
# "value must be between 1 and 100 inclusive". 50 = medium.
_DEFAULT_CASE_SEVERITY = 50

# Fields surfaced on each detection record returned to the page.
_ALERT_FIELDS = (
    "composite_id",
    "id",
    "device.hostname",
    "device.device_id",
    "severity",
    "tactic",
    "technique",
    "status",
    "created_timestamp",
)


def _alert_filter() -> str:
    """FQL filter for open alerts."""
    statuses = ",".join(f"status:'{s}'" for s in _OPEN_ALERT_STATUSES)
    return statuses


def _flatten_alert(alert: dict) -> dict:
    """Pluck the fields we care about from a raw FalconPy alert dict."""
    device = alert.get("device") or {}
    return {
        "composite_id": alert.get("composite_id") or alert.get("id"),
        "hostname": device.get("hostname"),
        "device_id": device.get("device_id"),
        "severity": alert.get("severity"),
        "tactic": alert.get("tactic"),
        "technique": alert.get("technique"),
        "status": alert.get("status"),
        "created_timestamp": alert.get("created_timestamp"),
    }


def find_open_detections_by_host(cid: Cid) -> dict[str, list[dict]]:
    """Return open detections grouped by hostname for a Falcon CID.

    Args:
        cid: Target CID credentials.

    Returns:
        Dict mapping hostname -> list of detection records. Detections without
        a hostname are reported and skipped.
    """
    falcon = Alerts(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    print(f"[*] Fetching open detections from {cid.name}...")
    composite_ids = paginate(
        falcon.query_alerts_v2,
        limit=1000,
        filter=_alert_filter(),
    )
    print(f"[+] Found {len(composite_ids)} open detection IDs")

    if not composite_ids:
        return {}

    # Chunk-fetch details. The POST entities API accepts a list per call;
    # 1000 matches the query limit and is well under typical body limits.
    print("[*] Fetching detection details...")
    alerts: list[dict] = []
    chunk_size = 1000
    for i in range(0, len(composite_ids), chunk_size):
        chunk = composite_ids[i : i + chunk_size]
        response = falcon.get_alerts_v2(composite_ids=chunk)
        if response["status_code"] != 200:
            raise RuntimeError(
                f"API error {response['status_code']}: {response['body']}"
            )
        alerts.extend(response["body"].get("resources", []))
    print(f"[+] Retrieved {len(alerts)} detection records")

    groups: dict[str, list[dict]] = {}
    skipped = 0
    for alert in alerts:
        record = _flatten_alert(alert)
        hostname = record["hostname"]
        if not hostname:
            skipped += 1
            continue
        groups.setdefault(hostname, []).append(record)

    if skipped:
        print(f"  [~] Skipped {skipped} detection(s) with no hostname")
    print(
        f"[+] Grouped detections across {len(groups)} host(s) "
        f"(total {sum(len(v) for v in groups.values())} detections)"
    )
    return groups


def list_open_cases(cid: Cid) -> list[dict]:
    """Return non-closed cases for a Falcon CID.

    Powers the per-host case-selection dropdown in the Streamlit page.
    """
    falcon = CaseManagement(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    print(f"[*] Fetching open cases from {cid.name}...")
    case_ids = paginate(falcon.query_case_ids, limit=500, filter=_OPEN_CASE_FILTER)
    print(f"[+] Found {len(case_ids)} open case ID(s)")

    if not case_ids:
        return []

    cases: list[dict] = []
    chunk_size = 100
    for i in range(0, len(case_ids), chunk_size):
        chunk = case_ids[i : i + chunk_size]
        response = falcon.get_cases(body={"ids": chunk})
        if response["status_code"] != 200:
            raise RuntimeError(
                f"API error {response['status_code']}: {response['body']}"
            )
        cases.extend(response["body"].get("resources", []))

    summaries = [
        {
            "id": c.get("id"),
            "name": c.get("name"),
            "status": c.get("status"),
            "created_time": c.get("created_time") or c.get("created"),
        }
        for c in cases
    ]
    summaries.sort(key=lambda c: (c.get("name") or "").lower())
    print(f"[+] Retrieved {len(summaries)} case record(s)")
    return summaries


def _validate_assignments(assignments: list[dict]) -> None:
    for idx, a in enumerate(assignments):
        has_id = bool(a.get("case_id"))
        has_name = bool(a.get("case_name"))
        if has_id == has_name:
            raise ValueError(
                f"Assignment #{idx} ({a.get('hostname')!r}): exactly one of "
                f"'case_id' or 'case_name' must be set"
            )
        if not a.get("alert_ids"):
            raise ValueError(
                f"Assignment #{idx} ({a.get('hostname')!r}): 'alert_ids' is empty"
            )


def _link_alerts_chunked(
    cm,
    case_id: str,
    hostname: str,
    alert_ids: list,
    result: dict,
) -> None:
    """Attach alerts to an existing case in safely-sized requests."""
    for i in range(0, len(alert_ids), _REQUEST_CHUNK):
        chunk = alert_ids[i : i + _REQUEST_CHUNK]
        response = cm.add_case_alert_evidence(
            id=case_id,
            alerts=[{"id": aid} for aid in chunk],
        )
        if response["status_code"] in (200, 201, 202):
            result["alerts_linked"] += len(chunk)
            print(
                f"  [+] {hostname}: linked chunk of {len(chunk)} alert(s) "
                f"to {case_id}"
            )
        else:
            result["errors"] += 1
            print(
                f"  [-] {hostname}: add_case_alert_evidence failed: "
                f"{response['body']}",
                file=sys.stderr,
            )
        time.sleep(0.5)


def _create_case_with_alerts(
    cm,
    *,
    name: str,
    description: str,
    alert_ids: list,
    hostname: str,
    result: dict,
) -> str | None:
    """Create one case carrying up to ``_MAX_ALERTS_PER_CASE`` alerts.

    The first request piggybacks evidence on the create call (capped at
    ``_REQUEST_CHUNK``). Any trailing alerts within the per-case cap are
    appended via ``add_case_alert_evidence``.
    """
    if len(alert_ids) > _MAX_ALERTS_PER_CASE:
        raise ValueError(
            f"Internal error: pack of {len(alert_ids)} exceeds per-case cap "
            f"{_MAX_ALERTS_PER_CASE}"
        )
    head = alert_ids[:_REQUEST_CHUNK]
    tail = alert_ids[_REQUEST_CHUNK:]
    response = cm.create_case(
        name=name,
        description=description,
        severity=_DEFAULT_CASE_SEVERITY,
        evidence={"alerts": [{"id": aid} for aid in head]},
    )
    if response["status_code"] not in (200, 201):
        result["errors"] += 1
        print(
            f"  [-] {hostname}: create_case {name!r} failed: {response['body']}",
            file=sys.stderr,
        )
        return None
    resources = response["body"].get("resources") or []
    if not resources:
        result["errors"] += 1
        print(
            f"  [-] {hostname}: create_case {name!r} returned no resources: "
            f"{response['body']}",
            file=sys.stderr,
        )
        return None
    first = resources[0]
    case_id = first.get("id") if isinstance(first, dict) else first
    result["cases_created"] += 1
    result["alerts_linked"] += len(head)
    print(
        f"  [+] {hostname}: created case {case_id} ({name!r}) with "
        f"{len(head)} alert(s)"
    )
    if tail:
        _link_alerts_chunked(cm, case_id, hostname, tail, result)
    return case_id


def _fetch_case(cm, case_id: str) -> dict | None:
    """Read a single case for capacity + name lookup."""
    response = cm.get_cases(body={"ids": [case_id]})
    if response["status_code"] != 200:
        print(
            f"  [-] get_cases({case_id}) failed: {response['body']}",
            file=sys.stderr,
        )
        return None
    resources = response["body"].get("resources") or []
    return resources[0] if resources else None


def correlate_detections_to_cases(
    cid: Cid,
    assignments: list[dict],
    *,
    dry_run: bool = False,
) -> dict:
    """Attach detections to existing cases or create new cases per host.

    Falcon caps each case at ``_MAX_ALERTS_PER_CASE`` total alerts. When an
    assignment exceeds the destination case's remaining capacity, this
    function fills the chosen case to the cap and spills the remainder into
    auto-numbered overflow cases named ``"<base> (part N)"``.

    Args:
        cid: Target CID credentials.
        assignments: Per-host operator decisions. Each item must have:
            ``hostname`` (str), ``alert_ids`` (non-empty list of composite IDs),
            and exactly one of ``case_id`` (existing case) or ``case_name``
            (new case to create).
        dry_run: If True, log the planned splits (including a read-only
            existing-case capacity probe) without performing any writes.

    Returns:
        Dict with keys: cases_created, cases_reused, alerts_linked, errors.
    """
    _validate_assignments(assignments)
    result = {"cases_created": 0, "cases_reused": 0, "alerts_linked": 0, "errors": 0}

    if not assignments:
        print("[*] No assignments to apply")
        return result

    cm = CaseManagement(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    for a in assignments:
        hostname = a["hostname"]
        alert_ids = list(a["alert_ids"])
        description = f"Auto-correlated by burd for host {hostname}"

        if a.get("case_id"):
            case_id = a["case_id"]
            existing = _fetch_case(cm, case_id)
            if existing is None:
                result["errors"] += 1
                continue
            existing_count = len(
                (existing.get("evidence") or {}).get("alerts") or []
            )
            base_name = existing.get("name") or f"Case {case_id}"
            capacity = max(0, _MAX_ALERTS_PER_CASE - existing_count)
            print(
                f"[*] {hostname}: existing case {case_id} holds "
                f"{existing_count}/{_MAX_ALERTS_PER_CASE} alert(s); capacity "
                f"{capacity}"
            )

            head = alert_ids[:capacity]
            spill = alert_ids[capacity:]

            if head:
                print(
                    f"[*] {hostname}: linking {len(head)} alert(s) to "
                    f"existing case {case_id}..."
                )
                if dry_run:
                    print(
                        f"  [DRY RUN] Would link {len(head)} alert(s) to "
                        f"{case_id}"
                    )
                else:
                    _link_alerts_chunked(cm, case_id, hostname, head, result)
                    result["cases_reused"] += 1
            elif not spill:
                print(f"  [~] {hostname}: nothing to do (case full, no spill)")
            else:
                print(
                    f"  [~] {hostname}: existing case full; all alerts will "
                    f"spill into new cases"
                )

            part = 2
            while spill:
                batch = spill[:_MAX_ALERTS_PER_CASE]
                spill = spill[_MAX_ALERTS_PER_CASE:]
                spill_name = f"{base_name} (part {part})"
                print(
                    f"[*] {hostname}: spilling {len(batch)} alert(s) into "
                    f"new case {spill_name!r}..."
                )
                if dry_run:
                    print(
                        f"  [DRY RUN] Would create case {spill_name!r} with "
                        f"{len(batch)} alert(s)"
                    )
                else:
                    _create_case_with_alerts(
                        cm,
                        name=spill_name,
                        description=description,
                        alert_ids=batch,
                        hostname=hostname,
                        result=result,
                    )
                part += 1
        else:
            base_name = a["case_name"]
            part = 1
            remaining = alert_ids
            while remaining:
                batch = remaining[:_MAX_ALERTS_PER_CASE]
                remaining = remaining[_MAX_ALERTS_PER_CASE:]
                name = base_name if part == 1 else f"{base_name} (part {part})"
                print(
                    f"[*] {hostname}: creating case {name!r} with "
                    f"{len(batch)} alert(s)..."
                )
                if dry_run:
                    print(
                        f"  [DRY RUN] Would create case {name!r} with "
                        f"{len(batch)} alert(s)"
                    )
                else:
                    _create_case_with_alerts(
                        cm,
                        name=name,
                        description=description,
                        alert_ids=batch,
                        hostname=hostname,
                        result=result,
                    )
                part += 1

    print(
        f"[+] Correlation complete: {result['cases_created']} created, "
        f"{result['cases_reused']} reused, {result['alerts_linked']} alerts "
        f"linked, {result['errors']} error(s)"
    )
    return result


def close_case_and_resolve_alerts(
    cid: Cid,
    case_id: str,
    *,
    dry_run: bool = False,
) -> dict:
    """Close a case and mark its attached alerts as ``closed``.

    Falcon does not cascade case status to alerts. This helper reads the
    case's ``evidence.alerts`` list, sets each alert to ``status='closed'``
    via ``Alerts.update_alerts_v3``, then closes the case itself via
    ``CaseManagement.update_case_fields``.

    Args:
        cid: Target CID credentials.
        case_id: ID of the case to close.
        dry_run: If True, log the planned actions without performing writes
            (the case fetch is read-only).

    Returns:
        Dict with keys: alerts_closed, alerts_errors, case_closed (bool),
        case_error (str or None).
    """
    result = {
        "alerts_closed": 0,
        "alerts_errors": 0,
        "case_closed": False,
        "case_error": None,
    }

    cm = CaseManagement(
        client_id=cid.client_id,
        client_secret=cid.client_secret,
        base_url=cid.base_url,
    )

    print(f"[*] Fetching case {case_id}...")
    case = _fetch_case(cm, case_id)
    if case is None:
        result["case_error"] = "case fetch failed"
        return result

    alert_entries = (case.get("evidence") or {}).get("alerts") or []
    alert_ids = [
        e.get("id") if isinstance(e, dict) else e
        for e in alert_entries
        if (e.get("id") if isinstance(e, dict) else e)
    ]
    case_name = case.get("name") or case_id
    case_status = case.get("status")
    print(
        f"[+] Case {case_name!r} status={case_status} with "
        f"{len(alert_ids)} attached alert(s)"
    )

    if dry_run:
        print(f"[DRY RUN] Would close {len(alert_ids)} alert(s) and case {case_id}")
        return result

    if alert_ids:
        alerts_api = Alerts(
            client_id=cid.client_id,
            client_secret=cid.client_secret,
            base_url=cid.base_url,
        )
        chunk_size = 500
        for i in range(0, len(alert_ids), chunk_size):
            chunk = alert_ids[i : i + chunk_size]
            response = alerts_api.update_alerts_v3(
                composite_ids=chunk,
                update_status="closed",
            )
            if response["status_code"] in (200, 201, 202, 204):
                result["alerts_closed"] += len(chunk)
                print(f"  [+] Closed chunk of {len(chunk)} alert(s)")
            else:
                result["alerts_errors"] += 1
                print(
                    f"  [-] update_alerts_v3 failed: {response['body']}",
                    file=sys.stderr,
                )
            time.sleep(0.5)
    else:
        print("  [~] No alerts attached to case; skipping alert close")

    print(f"[*] Closing case {case_id}...")
    response = cm.update_case_fields(id=case_id, fields={"status": "closed"})
    if response["status_code"] in (200, 201, 202, 204):
        result["case_closed"] = True
        print(f"  [+] Case {case_id} closed")
    else:
        result["case_error"] = str(response["body"])
        print(
            f"  [-] update_case_fields failed: {response['body']}",
            file=sys.stderr,
        )

    print(
        f"[+] Done: {result['alerts_closed']} alert(s) closed, "
        f"case_closed={result['case_closed']}, "
        f"alert_errors={result['alerts_errors']}"
    )
    return result
