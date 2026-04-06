"""Burd — Streamlit entry point."""

import streamlit as st

from burd.auth import Cid

st.set_page_config(page_title="Burd", page_icon=":eagle:", layout="wide")

# ── Sidebar: CID credential management ──────────────────────────────────

if "cids" not in st.session_state:
    st.session_state["cids"] = {}

with st.sidebar:
    st.header("CID Credentials")

    with st.form("add_cid", clear_on_submit=True):
        name = st.text_input("CID Name")
        client_id = st.text_input("Client ID")
        client_secret = st.text_input("Client Secret", type="password")
        base_url = st.text_input("Base URL", value="auto")
        submitted = st.form_submit_button("Add CID")

    if submitted:
        if name and client_id and client_secret:
            st.session_state["cids"][name] = Cid(
                name=name,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url or "auto",
            )
            st.rerun()
        else:
            st.error("Name, Client ID, and Client Secret are required.")

    if st.session_state["cids"]:
        st.subheader("Configured CIDs")
        for cid_name, cid in list(st.session_state["cids"].items()):
            col1, col2 = st.columns([3, 1])
            col1.write(f"**{cid_name}** ({cid.base_url})")
            if col2.button("Remove", key=f"rm_{cid_name}"):
                del st.session_state["cids"][cid_name]
                st.rerun()
    else:
        st.info("Add at least one CID to get started.")

# ── Navigation ───────────────────────────────────────────────────────────

pages = st.navigation([
    st.Page("page_ioc.py", title="IOC Migration", icon=":mag:"),
    st.Page("page_ioa.py", title="Custom IOA Migration", icon=":clipboard:"),
    st.Page("page_hosts.py", title="Host Deduplication", icon=":desktop_computer:"),
])
pages.run()
