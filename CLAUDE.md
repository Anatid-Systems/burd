# Burd

Python library + Streamlit app for programmatic interaction with CrowdStrike Falcon tenants. Features include migrating custom IOCs and Custom IOA rule groups between Falcon CIDs, and finding/removing duplicate host records within a CID. Built on [FalconPy](https://github.com/CrowdStrike/falconpy).

## Project layout

```
src/burd/
  __init__.py       # Public API re-exports
  auth.py           # Cid dataclass, load_cids(), select_cid()
  export.py         # export_iocs(), export_custom_ioas()
  hosts.py          # find_duplicate_hosts(), hide_duplicate_hosts()
  import_.py        # import_iocs(), import_custom_ioas()
  _pagination.py    # Generic FalconPy offset/total paginator
  _fields.py        # Read-only field sets + strip_fields() helper
  app/
    main.py         # Streamlit entry point (st.navigation + sidebar CID management)
    _stdout.py      # stdout/stderr capture helper for library calls
    page_ioc.py     # IOC Migration page
    page_ioa.py     # Custom IOA Migration page
    page_hosts.py   # Host Deduplication page
cids.toml           # CID credentials (gitignored, see cids.toml.example)
```

## Dev environment

- Python 3.12+, managed with `uv`
- Linter: `ruff` (dev dependency)
- Build backend: hatchling
- No test suite currently

```bash
uv pip install -e .                            # install
uv run streamlit run src/burd/app/main.py      # run app
uv run ruff check src/                         # lint
```

## Conventions

- Underscore-prefixed modules (`_pagination.py`, `_fields.py`) are internal helpers
- `import_.py` uses trailing underscore to avoid shadowing the `import` keyword
- FalconPy service classes (IOC, CustomIOA, Hosts) are instantiated per-function call, not shared
- All imported IOA groups and rules are created **disabled** by default
- Dedup keys: IOCs by `(type, value)`, IOA rule groups by `name`, hosts by `(hostname, mac_address)`
- Library functions use print-based progress output (`[*]`, `[+]`, `[-]`, `[~]` prefixes); the Streamlit app captures this via `_stdout.capture_output()` (contextlib.redirect_stdout/stderr) and renders it in `st.code()` blocks
- CID credentials are entered manually in the Streamlit sidebar and stored in `st.session_state`; `load_cids()` / `select_cid()` in `auth.py` are retained for library-only usage
- Each Streamlit page is standalone -- no shared state between pages other than the CID list

## Sensitive files

- `cids.toml` contains API secrets -- never commit it (already in .gitignore pattern expectations, but verify)
