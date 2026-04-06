# Burd

A Python library and Streamlit app for managing CrowdStrike Falcon tenants. Built on [FalconPy](https://github.com/CrowdStrike/falconpy).

## Features

- **IOC Migration** -- Export custom IOCs from a source CID and import them into a target CID, with automatic deduplication by type+value
- **Custom IOA Migration** -- Export and import Custom IOA rule groups (with embedded rules), deduplicated by group name; all imported groups and rules are created **disabled** for manual review
- **Host Deduplication** -- Find and hide duplicate host/sensor records within a CID, grouped by hostname+MAC address, keeping the most recently seen
- Dry-run mode on all write operations
- Each module is a standalone page in the Streamlit app

## Requirements

- Python 3.12+
- `uv` for dependency management
- A CrowdStrike Falcon API client per CID with appropriate scopes:
    - Custom IOC: Read/Write
    - Custom IOA Rules: Read/Write
    - Hosts: Read/Write (for host deduplication)

## Setup

```bash
uv pip install -e .
```

## Usage

Launch the Streamlit app:

```bash
uv run streamlit run src/burd/app/main.py
```

Add your CID credentials in the sidebar (name, client ID, client secret, base URL), then navigate between the three pages:

1. **IOC Migration** -- Select source/target CIDs, export IOCs, preview, then import (with dry-run toggle)
2. **Custom IOA Migration** -- Same workflow for IOA rule groups
3. **Host Deduplication** -- Select a CID, scan for duplicates, review the table, then hide stale records

You can also export/upload JSON files between sessions using the download and file upload controls on each page.

### Library usage

The `burd` package can also be used directly:

```python
import burd

cids = burd.load_cids()            # reads cids.toml
source = cids["prod-us2"]

iocs = burd.export_iocs(source)
ioas = burd.export_custom_ioas(source)

target = cids["staging"]
burd.import_iocs(target, iocs, dry_run=True)
burd.import_custom_ioas(target, ioas, dry_run=True)

duplicates, kept = burd.find_duplicate_hosts(source)
burd.hide_duplicate_hosts(source, duplicates, dry_run=True)
```
