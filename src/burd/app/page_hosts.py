"""Host Deduplication page."""

import json

import pandas as pd
import streamlit as st

import burd
from burd.app._stdout import capture_output

st.title("Host Deduplication")

cids = st.session_state.get("cids", {})
if not cids:
    st.warning("Add at least one CID in the sidebar.")
    st.stop()

# ── CID selection ────────────────────────────────────────────────────────

cid_name = st.selectbox("CID", list(cids), key="hosts_cid")
cid = cids[cid_name]

# ── Step 1: Scan for duplicates ──────────────────────────────────────────

st.subheader("1. Scan for Duplicates")

if st.button("Scan for Duplicates"):
    with st.spinner("Fetching hosts and scanning for duplicates..."):
        with capture_output() as log:
            duplicates, kept = burd.find_duplicate_hosts(cid)
    st.session_state["host_duplicates"] = duplicates
    st.session_state["host_kept"] = kept
    st.session_state["host_scan_log"] = log.getvalue()

if "host_scan_log" in st.session_state:
    st.code(st.session_state["host_scan_log"])

if "host_duplicates" in st.session_state:
    duplicates = st.session_state["host_duplicates"]
    kept = st.session_state["host_kept"]

    if not duplicates:
        st.success("No duplicates found.")
    else:
        st.info(
            f"**{len(duplicates)}** duplicate(s) found across "
            f"**{len(kept)}** groups with duplicates."
        )
        df = pd.DataFrame(duplicates)
        dedup_cols = ["hostname", "mac_address"]
        st.dataframe(
            df.style.applymap(
                lambda _: "background-color: #fff3cd",
                subset=[c for c in dedup_cols if c in df.columns],
            ),
            use_container_width=True,
        )
        st.download_button(
            "Download duplicates JSON",
            data=json.dumps(duplicates, indent=2),
            file_name="duplicate_hosts.json",
            mime="application/json",
        )

        # ── Step 2: Hide duplicates ─────────────────────────────────────

        st.subheader("2. Hide Duplicates")

        with st.form("hide_form"):
            dry_run = st.checkbox("Dry run", value=True)
            submitted = st.form_submit_button("Hide Duplicates")

        if submitted:
            with st.spinner("Hiding duplicate hosts..."):
                with capture_output() as log:
                    result = burd.hide_duplicate_hosts(
                        cid, duplicates, dry_run=dry_run
                    )
            st.code(log.getvalue())

            if not dry_run:
                col1, col2 = st.columns(2)
                col1.metric("Hidden", result["hidden"])
                col2.metric("Errors", result["errors"])
