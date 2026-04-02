"""CID credential management — load from TOML config and interactive selection."""

import tomllib
from dataclasses import dataclass


@dataclass
class Cid:
    """Credentials for a single CrowdStrike Falcon CID."""

    name: str
    client_id: str
    client_secret: str
    base_url: str = "auto"

    def __repr__(self):
        return f"Cid({self.name!r}, base_url={self.base_url!r})"


def load_cids(path="cids.toml"):
    """Load named CID credentials from a TOML config file.

    Expected format::

        [cids.my-prod]
        client_id = "..."
        client_secret = "..."
        base_url = "https://api.us-2.crowdstrike.com"

    Returns a dict mapping CID names to Cid objects.
    """
    with open(path, "rb") as f:
        config = tomllib.load(f)

    cids = {}
    for name, entry in config.get("cids", {}).items():
        cids[name] = Cid(
            name=name,
            client_id=entry["client_id"],
            client_secret=entry["client_secret"],
            base_url=entry.get("base_url", "auto"),
        )

    if not cids:
        raise ValueError(f"No CIDs found in {path}")

    return cids


def select_cid(cids, prompt="Select a CID"):
    """Interactively prompt the user to pick a CID from a numbered list.

    Args:
        cids: Dict of name -> Cid (as returned by load_cids).
        prompt: Header text shown above the list.

    Returns the selected Cid.
    """
    names = list(cids)

    print(f"\n{prompt}:")
    for i, name in enumerate(names, 1):
        cid = cids[name]
        print(f"  {i}. {name}  ({cid.base_url})")

    while True:
        choice = input(f"Enter number (1-{len(names)}): ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(names):
                selected = cids[names[idx]]
                print(f"  → {selected.name}\n")
                return selected
        except ValueError:
            pass
        print(f"  Invalid choice. Enter a number between 1 and {len(names)}.")
