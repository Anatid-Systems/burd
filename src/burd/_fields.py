"""Read-only field sets and stripping helper for FalconPy objects."""

IOC_READONLY_FIELDS = {
    "id", "created_on", "modified_on", "created_by", "modified_by",
    "from_parent", "deleted",
}

RULE_GROUP_READONLY_FIELDS = {
    "id", "created_on", "modified_on", "created_by", "modified_by",
    "customer_id", "committed_on", "version",
}

RULE_READONLY_FIELDS = {
    "id", "created_on", "modified_on", "created_by", "modified_by",
    "customer_id", "committed_on", "version", "magic_cookie",
    "instance_version", "pattern_id",
}


def strip_fields(obj, readonly_fields):
    return {k: v for k, v in obj.items() if k not in readonly_fields}
