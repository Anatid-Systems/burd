# Burd

A Python library and Streamlit app for managing CrowdStrike Falcon tenants. Built on [FalconPy](https://github.com/CrowdStrike/falconpy).

## Features

- **IOC Migration** -- Export custom IOCs from a source CID and import them into a target CID, with automatic deduplication by type+value
- **Custom IOA Migration** -- Export and import Custom IOA rule groups (with embedded rules), deduplicated by group name; all imported groups and rules are created **disabled** for manual review
- **Host Deduplication** -- Find and hide duplicate host/sensor records within a CID, grouped by hostname+MAC address, keeping the most recently seen. The duplicates table highlights the fields that triggered each match, and results can be filtered by CrowdStrike CID before hiding
- **Detection → Case Correlation** -- Group open detections by host, then attach them to existing cases or create new ones per host. Auto-spills into overflow cases when Falcon's per-case 100-alert cap would be exceeded. Includes a separate **Close Case + Resolve Alerts** action that closes a case *and* sets every attached alert to `closed` (Falcon does not cascade case status to alerts)
- Dry-run mode on all write operations
- Each module is a standalone page in the Streamlit app

## Requirements

- Python 3.12+
- `uv` for dependency management
- A CrowdStrike Falcon API client per CID with appropriate scopes:
    - Custom IOC: Read/Write
    - Custom IOA Rules: Read/Write
    - Hosts: Read/Write (for host deduplication)
    - Alerts: Read/Write (for detection → case correlation)
    - Case Management: Read/Write (for detection → case correlation)

## Setup

```bash
uv pip install -e .
```

## Usage

Launch the Streamlit app:

```bash
uv run streamlit run src/burd/app/main.py
```

Add your CID credentials in the sidebar (name, client ID, client secret, base URL), then navigate between the four pages:

1. **IOC Migration** -- Select source/target CIDs, export IOCs, preview, then import (with dry-run toggle)
2. **Custom IOA Migration** -- Same workflow for IOA rule groups
3. **Host Deduplication** -- Select a CID, scan for duplicates, optionally filter by CrowdStrike CID, then hide stale records
4. **Detection → Case** -- Select a CID, find open detections grouped by host, assign each host to an existing case or a new one, apply, and (separately) close cases while resolving their alerts

You can also export/upload JSON files between sessions using the download and file upload controls on each page.

### Library usage

The `burd` package can also be used directly:

```python
import burd

cids = burd.load_cids()            # reads cids.toml
source = cids["prod-us2"]

# Migration
iocs = burd.export_iocs(source)
ioas = burd.export_custom_ioas(source)

target = cids["staging"]
burd.import_iocs(target, iocs, dry_run=True)
burd.import_custom_ioas(target, ioas, dry_run=True)

# Host deduplication
duplicates, kept = burd.find_duplicate_hosts(source)
burd.hide_duplicate_hosts(source, duplicates, dry_run=True)

# Detection → case correlation
groups = burd.find_open_detections_by_host(source)
open_cases = burd.list_open_cases(source)

assignments = [
    {
        "hostname": "web-01",
        "alert_ids": [r["composite_id"] for r in groups["web-01"]],
        "case_name": "Triage: web-01",   # or use case_id=<existing>
    },
]
burd.correlate_detections_to_cases(source, assignments, dry_run=True)

# Close a case and mark its alerts closed
burd.close_case_and_resolve_alerts(source, "<case-id>", dry_run=True)
```
