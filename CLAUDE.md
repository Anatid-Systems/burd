# Burd

Python library + Jupyter notebook for programmatic interaction with CrowdStrike Falcon tenants. Features include migrating custom IOCs and Custom IOA rule groups between Falcon CIDs, and finding/removing duplicate host records within a CID. Built on [FalconPy](https://github.com/CrowdStrike/falconpy).

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
notebook.ipynb      # Interactive JupyterLab workflow
cids.toml           # CID credentials (gitignored, see cids.toml.example)
```

## Dev environment

- Python 3.12+, managed with `uv`
- Linter: `ruff` (dev dependency)
- Build backend: hatchling
- No test suite currently

```bash
uv pip install -e .          # install
uv run jupyter lab           # run notebook
uv run ruff check src/       # lint
```

## Conventions

- Underscore-prefixed modules (`_pagination.py`, `_fields.py`) are internal helpers
- `import_.py` uses trailing underscore to avoid shadowing the `import` keyword
- FalconPy service classes (IOC, CustomIOA, Hosts) are instantiated per-function call, not shared
- All imported IOA groups and rules are created **disabled** by default
- Dedup keys: IOCs by `(type, value)`, IOA rule groups by `name`, hosts by `(hostname, mac_address)`
- Print-based progress output (`[*]`, `[+]`, `[-]`, `[~]` prefixes)

## Sensitive files

- `cids.toml` contains API secrets -- never commit it (already in .gitignore pattern expectations, but verify)
