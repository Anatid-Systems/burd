"""Detection-to-Case correlation page."""

import json

import pandas as pd
import streamlit as st

import burd
from burd.app._stdout import capture_output

st.title("Detection → Case")

cids = st.session_state.get("cids", {})
if not cids:
    st.warning("Add at least one CID in the sidebar.")
    st.stop()

# ── CID selection ────────────────────────────────────────────────────────

cid_name = st.selectbox("CID", list(cids), key="cases_cid")
cid = cids[cid_name]

# When the CID changes, drop stale results so the operator can't apply
# assignments derived from a previous CID's data.
if st.session_state.get("cases_cid_loaded") != cid_name:
    for k in (
        "cases_groups",
        "cases_open_cases",
        "cases_find_log",
        "cases_apply_log",
        "cases_apply_result",
        "cases_close_log",
        "cases_close_result",
    ):
        st.session_state.pop(k, None)
    st.session_state["cases_cid_loaded"] = cid_name

# ── Step 1: Find open detections + open cases ───────────────────────────

st.subheader("1. Find Open Detections")

if st.button("Find Detections"):
    with st.spinner("Fetching detections and cases..."):
        with capture_output() as log:
            groups = burd.find_open_detections_by_host(cid)
            open_cases = burd.list_open_cases(cid)
    st.session_state["cases_groups"] = groups
    st.session_state["cases_open_cases"] = open_cases
    st.session_state["cases_find_log"] = log.getvalue()
    st.session_state.pop("cases_apply_log", None)
    st.session_state.pop("cases_apply_result", None)

if "cases_find_log" in st.session_state:
    st.code(st.session_state["cases_find_log"])

groups = st.session_state.get("cases_groups")
open_cases = st.session_state.get("cases_open_cases", [])

if groups is not None and not groups:
    st.success("No open detections found.")

# ── Steps 2/3: only render when detections are loaded ───────────────────

if groups:
    st.subheader("2. Assign Cases per Host")

    summary_rows = [
        {
            "hostname": host,
            "detections": len(records),
            "max_severity": max(
                (
                    r.get("severity")
                    for r in records
                    if r.get("severity") is not None
                ),
                default=None,
            ),
            "statuses": ", ".join(
                sorted({r.get("status") or "" for r in records})
            ),
        }
        for host, records in groups.items()
    ]
    st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)

    SKIP = "<skip>"
    CREATE_NEW = "<create new>"
    case_label_to_id: dict[str, str] = {}
    case_options = [SKIP, CREATE_NEW]
    for c in open_cases:
        cid_label = f"{c['name']} [{c['id']}]"
        case_label_to_id[cid_label] = c["id"]
        case_options.append(cid_label)

    st.caption(
        f"{len(open_cases)} existing open case(s) available. "
        "Pick one per host, choose **<create new>** to create a fresh case, "
        "or leave **<skip>** to ignore the host."
    )

    for hostname, records in groups.items():
        with st.expander(
            f"{hostname} — {len(records)} detection(s)", expanded=False
        ):
            st.dataframe(pd.DataFrame(records), use_container_width=True)
            col1, col2 = st.columns([1, 1])
            col1.selectbox(
                "Target case",
                case_options,
                key=f"cases_assign_target_{hostname}",
            )
            col2.text_input(
                "New case name (only used if 'create new' is selected)",
                key=f"cases_assign_newname_{hostname}",
                placeholder=f"Triage: {hostname}",
            )

    st.subheader("3. Apply")

    with st.form("cases_apply_form"):
        dry_run = st.checkbox("Dry run", value=True)
        submitted = st.form_submit_button("Apply Assignments")

    if submitted:
        assignments: list[dict] = []
        skipped_hosts: list[str] = []
        invalid_hosts: list[str] = []

        for hostname, records in groups.items():
            target = st.session_state.get(
                f"cases_assign_target_{hostname}", SKIP
            )
            if target == SKIP:
                skipped_hosts.append(hostname)
                continue

            alert_ids = [
                r["composite_id"] for r in records if r.get("composite_id")
            ]
            if not alert_ids:
                invalid_hosts.append(hostname)
                continue

            if target == CREATE_NEW:
                new_name = (
                    st.session_state.get(
                        f"cases_assign_newname_{hostname}", ""
                    )
                    or ""
                ).strip()
                if not new_name:
                    invalid_hosts.append(hostname)
                    continue
                assignments.append(
                    {
                        "hostname": hostname,
                        "alert_ids": alert_ids,
                        "case_name": new_name,
                    }
                )
            else:
                assignments.append(
                    {
                        "hostname": hostname,
                        "alert_ids": alert_ids,
                        "case_id": case_label_to_id[target],
                    }
                )

        if invalid_hosts:
            st.error(
                "These hosts have **<create new>** selected without a case "
                "name: " + ", ".join(invalid_hosts)
            )
        elif not assignments:
            st.warning("No hosts selected for correlation.")
        else:
            if skipped_hosts:
                st.info(
                    f"Skipping {len(skipped_hosts)} host(s) marked <skip>."
                )
            with st.spinner("Applying assignments..."):
                with capture_output() as log:
                    result = burd.correlate_detections_to_cases(
                        cid, assignments, dry_run=dry_run
                    )
            st.session_state["cases_apply_log"] = log.getvalue()
            st.session_state["cases_apply_result"] = result

    if "cases_apply_log" in st.session_state:
        st.code(st.session_state["cases_apply_log"])

    if "cases_apply_result" in st.session_state:
        result = st.session_state["cases_apply_result"]
        cols = st.columns(4)
        cols[0].metric("Cases created", result["cases_created"])
        cols[1].metric("Cases reused", result["cases_reused"])
        cols[2].metric("Alerts linked", result["alerts_linked"])
        cols[3].metric("Errors", result["errors"])

    st.download_button(
        "Download detections JSON",
        data=json.dumps(groups, indent=2, default=str),
        file_name="open_detections_by_host.json",
        mime="application/json",
    )

# ── Step 4: Close case + resolve alerts (always available) ──────────────

st.subheader("4. Close Case + Resolve Alerts")
st.caption(
    "Closes the selected case **and** sets every alert attached to it to "
    "`status='closed'` via the Alerts API. Falcon does not cascade case "
    "status to alerts; this button is the cascade."
)

if st.button("Refresh open case list", key="cases_close_refresh"):
    with st.spinner("Loading cases..."):
        with capture_output() as log:
            st.session_state["cases_open_cases"] = burd.list_open_cases(cid)
    st.code(log.getvalue())

close_options = st.session_state.get("cases_open_cases", [])

if not close_options:
    st.info(
        "No open cases loaded. Click **Find Detections** above or "
        "**Refresh open case list** to populate."
    )
else:
    close_label_to_id = {
        f"{c['name']} [{c['id']}]": c["id"] for c in close_options
    }
    with st.form("cases_close_form"):
        target_label = st.selectbox(
            "Case to close",
            list(close_label_to_id),
            key="cases_close_target",
        )
        close_dry_run = st.checkbox(
            "Dry run", value=True, key="cases_close_dry_run"
        )
        close_submitted = st.form_submit_button(
            "Close Case + Resolve Alerts"
        )

    if close_submitted and target_label:
        target_case_id = close_label_to_id[target_label]
        with st.spinner("Closing case and resolving alerts..."):
            with capture_output() as log:
                close_result = burd.close_case_and_resolve_alerts(
                    cid, target_case_id, dry_run=close_dry_run
                )
        st.session_state["cases_close_log"] = log.getvalue()
        st.session_state["cases_close_result"] = close_result

if "cases_close_log" in st.session_state:
    st.code(st.session_state["cases_close_log"])

if "cases_close_result" in st.session_state:
    cr = st.session_state["cases_close_result"]
    cols = st.columns(3)
    cols[0].metric("Alerts closed", cr["alerts_closed"])
    cols[1].metric("Case closed", "yes" if cr["case_closed"] else "no")
    cols[2].metric("Alert errors", cr["alerts_errors"])
    if cr["case_error"]:
        st.error(f"Case close error: {cr['case_error']}")
