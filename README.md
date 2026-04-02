# Burd

A Python library and notebook for migrating custom IOCs and Custom IOA rule groups between CrowdStrike Falcon CIDs. Built on top of [FalconPy](https://github.com/CrowdStrike/falconpy). Initially developed for personal usage, please don't expect high-quality code.

## Purpose

- Export all custom IOCs and IOA rule groups from a source CID
- Import them into one or more target CIDs
    - Automatically dedupes IOCs by type+value and IOA groups by name
- Creates all imported IOA groups and rules disabled for manual review
- New: dry-run mode
- Runs in a JupyterLab notebook because why not.

## Requirements

- Python 3.12+
- A CrowdStrike Falcon API client per CID with appropriate scopes
    - At a minimum, your clients need:
        - Custom IOC: Read/Write, 
        - Custom IOA Rules: Read/Write

## Setup

You will need `uv` to use Burd. Don't hate.

```bash
uv pip install -e .
```

Copy the example config and fill in your CID credentials:

```bash
cp cids.toml.example cids.toml
```

Each CID gets a named section in `cids.toml`:

```toml
[cids.prod-us2]
client_id = "..."
client_secret = "..."
base_url = "https://api.us-2.crowdstrike.com"

[cids.staging]
client_id = "..."
client_secret = "..."
base_url = "auto"
```

## Usage

Start JupyterLab in the source directory and run `notebook.ipynb`.

```bash
uv run jupyter lab notebook.ipynb
```

The notebook will prompt you to select a source and target CID, then walk you through the export and import steps.

You can also use the `burd` package directly:

```python
import burd

cids = burd.load_cids()            # reads cids.toml
source = cids["prod-us2"]

iocs = burd.export_iocs(source)
ioas = burd.export_custom_ioas(source)

target = cids["staging"]
burd.import_iocs(target, iocs, dry_run=True)
burd.import_custom_ioas(target, ioas, dry_run=True)
```
