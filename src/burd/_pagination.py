"""Generic pagination for FalconPy API calls that return offset/total."""


def paginate(fn, *, limit=500, **kwargs):
    results = []
    offset = 0

    while True:
        response = fn(offset=offset, limit=limit, **kwargs)
        if response["status_code"] != 200:
            raise RuntimeError(
                f"API error {response['status_code']}: {response['body']}"
            )

        resources = response["body"].get("resources", [])
        results.extend(resources)

        meta = response["body"].get("meta", {}).get("pagination", {})
        total = meta.get("total", 0)
        offset += len(resources)

        if offset >= total or not resources:
            break

    return results
