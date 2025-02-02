resource_definitions = [
    {
        "id": "1",  # Unique ID for the resource
        "path": "organizations/{org_id}/get-account",
        "methods": ["GET"],
        "name": "Empower",
        "description": "Retrieve details of current user",
    },
    {
        "id": "2",  # Unique ID for the resource
        "path": "organizations/{org_id}/tenants/{tenant_id}/extension/trusted-domains",
        "methods": ["GET", "POST", "DELETE"],
        "name": "Chrome Extension",
        "description": "Manage tenant-level trusted domains",
    },
    {
        "id": "3",  # Unique ID for the resource
        "path": "organizations/{tent}/integration-stats",
        "methods": ["GET", "POST", "DELETE"],
        "name": "Chrome Extension",
        "description": "Manage tenant-level trusted domains",
    },
    # Add more resources
]


def match_resource(request_path, request_method, resources):
    request_segments = request_path.strip("/").split("/")

    for resource in resources:
        resource_segments = resource["path"].strip("/").split("/")
        if len(request_segments) != len(resource_segments):
            continue  # Skip if segment lengths don't match

        params = {}
        is_match = True

        for req_seg, res_seg in zip(request_segments, resource_segments):
            if res_seg.startswith("{") and res_seg.endswith("}"):
                # Extract parameter name and value
                param_name = res_seg[1:-1]
                params[param_name] = req_seg
            elif req_seg != res_seg:
                is_match = False
                break

        if is_match and request_method in resource["methods"]:
            return {
                "id": resource["id"],  # Include the resource ID
                "resource_name": resource["name"],
                "description": resource["description"],
                "matched_pattern": resource["path"],  # Include the matched resource pattern
                "parameters": params,
            }

    return None  # No match found


matched_resource = match_resource(
    "organizations/123123/tenants/123123/extension/trusted-domains",
    "GET",
    resource_definitions,
)

print(matched_resource)
