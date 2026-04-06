"""IOC Migration page."""

import json

import streamlit as st

import burd
from burd.app._stdout import capture_output

st.title("IOC Migration")

cids = st.session_state.get("cids", {})
if not cids:
    st.warning("Add at least one CID in the sidebar.")
    st.stop()

cid_names = list(cids)

# ── CID selection ────────────────────────────────────────────────────────

col_src, col_tgt = st.columns(2)
with col_src:
    source_name = st.selectbox("Source CID (export from)", cid_names, key="ioc_src")
with col_tgt:
    target_name = st.selectbox("Target CID (import into)", cid_names, key="ioc_tgt")

source_cid = cids[source_name]
target_cid = cids[target_name]

# ── Step 1: Export IOCs ──────────────────────────────────────────────────

st.subheader("1. Export IOCs")

if st.button("Export IOCs from source"):
    with st.spinner(f"Exporting IOCs from {source_cid.name}..."):
        with capture_output() as log:
            iocs = burd.export_iocs(source_cid)
    st.session_state["iocs"] = iocs
    st.session_state["ioc_export_log"] = log.getvalue()

if "ioc_export_log" in st.session_state:
    st.code(st.session_state["ioc_export_log"])

# Allow uploading a previously exported JSON file
uploaded = st.file_uploader("Or upload IOCs JSON", type=["json"], key="ioc_upload")
if uploaded is not None:
    st.session_state["iocs"] = json.load(uploaded)
    st.success(f"Loaded {len(st.session_state['iocs'])} IOCs from file.")

# ── Step 2: Preview & Import ─────────────────────────────────────────────

if "iocs" in st.session_state:
    iocs = st.session_state["iocs"]
    st.subheader("2. Import IOCs")
    st.info(f"**{len(iocs)}** IOCs ready to import into **{target_cid.name}**.")

    st.dataframe(iocs, use_container_width=True, height=300)
    st.download_button(
        "Download IOCs JSON",
        data=json.dumps(iocs, indent=2),
        file_name="iocs.json",
        mime="application/json",
    )

    with st.form("ioc_import_form"):
        dry_run = st.checkbox("Dry run", value=True)
        submitted = st.form_submit_button("Run Import")

    if submitted:
        with st.spinner("Importing IOCs..."):
            with capture_output() as log:
                result = burd.import_iocs(target_cid, iocs, dry_run=dry_run)
        st.code(log.getvalue())

        col1, col2, col3 = st.columns(3)
        col1.metric("Created", result["created"])
        col2.metric("Skipped", result["skipped"])
        col3.metric("Errors", result["errors"])
