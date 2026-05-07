"""Custom IOA Migration page."""

import json

import streamlit as st

import burd
from burd.app._stdout import capture_output

st.title("Custom IOA Migration")

cids = st.session_state.get("cids", {})
if not cids:
    st.warning("Add at least one CID in the sidebar.")
    st.stop()

cid_names = list(cids)

# ── CID selection ────────────────────────────────────────────────────────

col_src, col_tgt = st.columns(2)
with col_src:
    source_name = st.selectbox("Source CID (export from)", cid_names, key="ioa_src")
with col_tgt:
    target_name = st.selectbox("Target CID (import into)", cid_names, key="ioa_tgt")

source_cid = cids[source_name]
target_cid = cids[target_name]

# ── Step 1: Export IOA rule groups ───────────────────────────────────────

st.subheader("1. Export Custom IOA Rule Groups")

if st.button("Export IOA rule groups from source"):
    with st.spinner(f"Exporting Custom IOA rule groups from {source_cid.name}..."):
        with capture_output() as log:
            groups = burd.export_custom_ioas(source_cid)
    st.session_state["ioa_groups"] = groups
    st.session_state["ioa_export_log"] = log.getvalue()

if "ioa_export_log" in st.session_state:
    st.code(st.session_state["ioa_export_log"])

# Allow uploading a previously exported JSON file
uploaded = st.file_uploader(
    "Or upload IOA rule groups JSON", type=["json"], key="ioa_upload"
)
if uploaded is not None:
    st.session_state["ioa_groups"] = json.load(uploaded)
    st.success(f"Loaded {len(st.session_state['ioa_groups'])} rule groups from file.")

# ── Step 2: Preview & Import ─────────────────────────────────────────────

if "ioa_groups" in st.session_state:
    groups = st.session_state["ioa_groups"]
    st.subheader("2. Import Custom IOA Rule Groups")
    st.info(
        f"**{len(groups)}** rule groups ready to import into **{target_cid.name}**."
    )

    # Summary table: group name + rule count
    summary = [
        {"name": g.get("name"), "rules": len(g.get("rules", []))} for g in groups
    ]
    st.dataframe(summary, use_container_width=True)

    st.download_button(
        "Download IOA rule groups JSON",
        data=json.dumps(groups, indent=2),
        file_name="custom_ioas.json",
        mime="application/json",
    )

    with st.form("ioa_import_form"):
        dry_run = st.checkbox("Dry run", value=True)
        submitted = st.form_submit_button("Run Import")

    if submitted:
        with st.spinner("Importing Custom IOA rule groups..."):
            with capture_output() as log:
                result = burd.import_custom_ioas(target_cid, groups, dry_run=dry_run)
        st.code(log.getvalue())

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Groups Created", result["created_groups"])
        col2.metric("Groups Skipped", result["skipped_groups"])
        col3.metric("Group Errors", result["error_groups"])
        col4.metric("Rules Created", result["created_rules"])
