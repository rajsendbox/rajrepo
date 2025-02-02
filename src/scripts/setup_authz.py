import os
import json
import logging
import requests
import yaml
import sys

from pathlib import Path
from keycloak import KeycloakAdmin


# Use pathlib to define the path
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"

# Set up logger
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Configure logger
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()  # Logs to console
    ]
)

logger = logging.getLogger(__name__)

if len(sys.argv) != 6:
    logger.error("Usage: setup_authz.py <REALM_NAME> <REALM_ADMIN_USER> <REALM_ADMIN_PASSWORD> <KEYCLOAK_BASE_URL> <ENV_NAME>")
    sys.exit(1)

# Extract arguments from command line
REALM_NAME = sys.argv[1]
REALM_ADMIN_USER = sys.argv[2]
REALM_ADMIN_PASSWORD = sys.argv[3]
KEYCLOAK_BASE_URL = sys.argv[4]
ENV_NAME = sys.argv[5]
        

# Initialize Keycloak Admin
def init_keycloak():
    print("[ Initializing KeycloakAdmin ...]")
    return KeycloakAdmin(
        server_url=KEYCLOAK_BASE_URL,
        username=REALM_ADMIN_USER,
        password=REALM_ADMIN_PASSWORD,
        realm_name=REALM_NAME,
        user_realm_name=REALM_NAME
    )

def get_admin_token():
    """Obtain an admin token from Keycloak."""
    print("[ Getting admin_token ...]")
    
    try:
        response = requests.post(
            f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": REALM_ADMIN_USER,
                "password": REALM_ADMIN_PASSWORD,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.RequestException as e:
        raise Exception(f"Failed to get admin token: {str(e)}")


# Load YAML configuration
def load_config(yaml_file):
    print("[ Loading config ...]")
    
    with open(yaml_file, "r") as file:
        return yaml.safe_load(file)

# Create Scopes
def create_scopes(keycloak_admin: KeycloakAdmin, client_id, scopes):
    print(f"[ Creating scopes for client_id: {client_id} ...]")
    
    # Fetch existing scopes from Keycloak
    existing_scopes = {scope["name"]: scope for scope in keycloak_admin.get_client_authz_scopes(client_id=client_id)}
    print(f"[ Existing scopes: {list(existing_scopes.keys())} ]")
    
    scope_ids = {}
    
    for scope in scopes:
        scope_name = scope["name"]
        scope_description = scope["description"]
        
        if scope_name in existing_scopes:
            # If the scope already exists
            print(f"   - [ Scope '{scope_name}' already exists. Skipping... ]")
            scope_ids[scope_name] = existing_scopes[scope_name]
        else:
            # If the scope doesn't exist, create it
            payload = {
                "id": scope_name,
                "name": scope_name,
                "displayName": scope_description
            }
            response = keycloak_admin.create_client_authz_scopes(client_id=client_id, payload=payload)
            scope_ids[scope_name] = response
            print(f"   - [ Created Scope: {scope_name} with ID {response} ... ]")
            
    print(f"[ Final scope_ids: {scope_ids} ]")
    return scope_ids

"""
# Create Resources
def create_resources(keycloak_admin: KeycloakAdmin, client_id, resources, scope_ids):
    print(f"[ Creating resouces for client_id: {client_id} ...]")
    
    # Fetch existing resources from Keycloak
    existing_resources = {res["name"]: res for res in keycloak_admin.get_client_authz_settings(client_id=client_id)["resources"]}
    print("Existing resources: ", list(existing_resources.keys()))
    
    resource_ids = {}
    
    for resource in resources:
        resource_name = resource["name"]
        resource_uris = resource["uris"]
        resource_scopes = [{"name": scope} for scope in resource["scopes"] if scope in scope_ids]
        
        if resource_name in existing_resources:
            # If the resource already exists, log the message
            print(f"   - [ Resource '{resource_name}' already exists. Skipping... ]")
            resource_ids[resource_name] = existing_resources[resource_name]
        else:
            # If the resource doesn't exist, create it
            payload = {
                "name": resource_name,
                "uris": resource_uris,
                "scopes": resource_scopes,
            }
            response = keycloak_admin.create_client_authz_resource(client_id=client_id, payload=payload)
            resource_ids[resource_name] = response
            print(f"   - [ Created Resource: {resource_name} with ID {response} ... ]")
    
    print(f"[ Final resource_ids: {resource_ids} ]")
    return resource_ids
"""

def delete_all_resources(keycloak_admin: KeycloakAdmin, client_id):
    """
    Deletes all resources for a given client in Keycloak.
    
    Parameters:
        keycloak_admin (KeycloakAdmin): The Keycloak admin instance.
        client_id (str): The client ID for which resources need to be deleted.
    """
    print(f"[ Deleting all resources for client_id: {client_id} ...]")

    try:
        # Fetch existing resources
        existing_resources = keycloak_admin.get_client_authz_resources(client_id=client_id)
        print(f"[ Found {len(existing_resources)} resources to delete ...]")

        for resource in existing_resources:
            resource_name = resource["name"]
            resource_id = resource["_id"]

            try:
                # Delete the resource
                keycloak_admin.delete_client_authz_resource(client_id=client_id, resource_id=resource_id)
                print(f"   - [ Deleted Resource: {resource_name} with ID {resource_id} ... ]")
            except Exception as e:
                print(f"   [ X | Error deleting resource '{resource_name}' with ID {resource_id}]: {e}")

        print("[ All resources deleted successfully ...]")
    except Exception as e:
        print(f"[ X | Error fetching resources for client {client_id}: {e}]")

# Create Resources
def create_resources(keycloak_admin: KeycloakAdmin, client_id, resources, scope_ids):
    """
    Create resources in Keycloak and clean up resources not defined in the configuration.

    Args:
        keycloak_admin (KeycloakAdmin): Keycloak admin client instance.
        client_id (str): Keycloak client ID.
        resources (list): List of resources from the updated configuration.
        scope_ids (dict): Mapping of scope names to their IDs.

    Returns:
        dict: Dictionary of created or existing resource IDs.
    """
    print(f"[ Creating resources for client_id: {client_id} ...]")

    # Fetch existing resources from Keycloak
    existing_resources = {
        res["name"].strip("/"): res for res in keycloak_admin.get_client_authz_resources(client_id=client_id)
    }
    print("Existing resources: ", list(existing_resources.keys()))

    # Build a set of normalized resource names from the configuration
    configured_resource_names = {res["name"].strip("/") for res in resources}

    resource_ids = {}

    # Create or update resources based on the configuration
    for resource in resources:
        resource_name = resource["name"].strip("/")

        # Process URIs: Trim starting and ending '/' for each URI
        trimmed_uris = [uri.strip("/") for uri in resource.get("uris", [])]

        if resource_name in existing_resources:
            print(f"   - [ Resource '{resource_name}' already exists. Skipping... ]")
            resource_ids[resource_name] = {
                "id": existing_resources[resource_name]["_id"],  # Ensure ID is captured properly
                **existing_resources[resource_name]
            }
        else:
            try:
                payload = {
                    "name": resource_name,
                    "uris": trimmed_uris,
                    "scopes": [{"name": scope} for scope in resource["scopes"] if scope in scope_ids],
                }
                response = keycloak_admin.create_client_authz_resource(client_id=client_id, payload=payload)

                # Ensure the ID is captured correctly
                resource_ids[resource_name] = {
                    "id": response["_id"],  # Use '_id' as returned by Keycloak
                    **response,
                }
                print(f"   - [ Created Resource: {resource_name} with ID {response['_id']} ... ]")

            except KeyError as ke:
                print(f"   [ X | KeyError while creating resource '{resource_name}']: {ke}")
            except Exception as e:
                print(f"   [ X | Unexpected error while creating resource '{resource_name}']: {e}")

    # Clean up resources not in the updated configuration
    for existing_resource_name, existing_resource in existing_resources.items():
        if existing_resource_name not in configured_resource_names:
            try:
                print(f"   - [ Removing Resource: {existing_resource_name} with ID {existing_resource['_id']} ... ]")
                keycloak_admin.delete_client_authz_resource(client_id, existing_resource["_id"])
            except Exception as e:
                print(f"   [ X | Error while deleting resource '{existing_resource_name}']: {e}")

    print("Final resource_ids: ", resource_ids)
    return resource_ids

# Create Policies
def create_policies(keycloak_admin: KeycloakAdmin, client_id, policies):
    print(f"[ Creating policies for client_id: {client_id} ...]")
    
    # Fetch existing policies
    existing_policies = {policy["name"]: policy for policy in keycloak_admin.get_client_authz_policies(client_id=client_id)}
    print("Existing policies: ", list(existing_policies.keys()))
    
    policy_ids = {}
    for policy in policies.get("custom_policies", []):
        
        policy_name = policy["name"]
        
        if policy_name in existing_policies:
            print(f"   - [ Policy '{policy_name}' already exists. Skipping... ]")
            policy_ids[policy_name] = existing_policies[policy_name]
        else:
            try:
                payload = {
                    "name": policy_name,
                    "logic": "POSITIVE",
                    "type": policy["type"],
                    "decisionStrategy": "UNANIMOUS",
                    "code": policy.get("code", "")
                }
                response = requests.post(
                    url=f"{KEYCLOAK_BASE_URL}/admin/realms/{REALM_NAME}/clients/{client_id}/authz/resource-server/policy/{policy['type'].lower()}",
                    data=json.dumps(payload),
                    headers={
                        'Authorization': f'Bearer {get_admin_token()}',
                        'content-type': 'application/json'
                    }
                )
                policy_ids[policy_name] = response.json()
                print(f"   - [ Created Custom Policy: {policy_name} with ID {response.json()} ...]")
            except Exception as e:
                print(f"   [ X | Error creating custom policy '{policy_name}']: {str(e)}")

    org_scope_policy_id = policy_ids.get('OrganizationScopePolicy', {}).get('id')
    
    # Create Role-Based Policies
    for policy in policies.get("role_policies", []):
        temp_policy_name = f'temp_{policy["name"]}'
        if temp_policy_name in existing_policies:
            print(f"   - [ Role Policy '{temp_policy_name}' already exists. Skipping... ]")
            policy_ids[temp_policy_name] = existing_policies[temp_policy_name]
        else:
            try:
                payload = {
                    "name": temp_policy_name,
                    "fetchRoles": False,
                    "type": "role",
                    "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "roles": [
                        {
                            "id": keycloak_admin.get_client_role_id(client_id, role),
                            "required": True
                        }
                        for role in policy["roles"]
                    ],
                }
                response = keycloak_admin.create_client_authz_role_based_policy(client_id=client_id, payload=payload)
                policy_ids[temp_policy_name] = response
                print(f"   - [ Created Role Policy: {temp_policy_name} with ID {response} ... ]")
            except Exception as e:
                logger.exception(f"   [ X | Error creating role policy '{temp_policy_name}']: {str(e)}")
                
        
    # Create Aggregate Policy
        aggregate_policy_name = policy["name"]
        if aggregate_policy_name in existing_policies:
            print(f"   - [ Aggregate Policy '{aggregate_policy_name}' already exists. Skipping... ]")
            policy_ids[aggregate_policy_name] = existing_policies[aggregate_policy_name]
        else:
            try:
                agg_payload = {
                    "name": aggregate_policy_name,
                    "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "policies": [
                        org_scope_policy_id, policy_ids[temp_policy_name]["id"]
                    ],
                }
                response = requests.post(
                    url=f"{KEYCLOAK_BASE_URL}/admin/realms/{REALM_NAME}/clients/{client_id}/authz/resource-server/policy/aggregate",
                    data=json.dumps(agg_payload),
                    headers={
                        'Authorization': f'Bearer {get_admin_token()}',
                        'content-type': 'application/json'
                    }
                )
                policy_ids[aggregate_policy_name] = response.json()
                print(f"   - [ Created Aggregate Policy: {aggregate_policy_name} with ID {response.json()} ... ]")
            except Exception as e:
                print(f"   [ X | Error creating aggregate policy '{aggregate_policy_name}']: {str(e)}")

    print(f"[ Final policy_ids: {policy_ids} ]")
    return policy_ids


def process_permissions_for_duplicates(permissions): 
    """
    Processes a list of permissions and ensures all permission names are unique,
    normalizing slashes and alerting about any slash issues. Removes duplicates and keeps only unique permissions.

    Args:
        permissions (list): A list of dictionaries, each representing a permission.

    Returns:
        list: A list of unique permissions.
    """
    def normalize_name(name):
        """
        Normalizes a permission name by removing redundant slashes and trailing slashes.

        Args:
            name (str): The original permission name.

        Returns:
            str: The normalized permission name.
        """
        if not name:
            return None
        return name.strip().rstrip("/").replace("//", "/")

    normalized_permissions = {}
    warnings = []

    # Process permissions and normalize names
    for permission in permissions:
        name = permission.get('name')
        if not name:
            raise ValueError("X | [ Permission dictionary must include a 'name' key. ")

        # Normalize the name for consistent comparison
        normalized_name = normalize_name(name)

        # Detect potential slash issues
        if name != normalized_name:
            warnings.append(f" [ Potential redundant or trailing slash in name ]: {name}")

        # Add to the normalized_permissions dictionary, keeping the first instance of a permission
        if normalized_name not in normalized_permissions:
            normalized_permissions[normalized_name] = permission

    if warnings:
        print("[ Warnings detected ]:")
        for warning in warnings:
            print(warning)

    print("[ All duplicate permissions removed. Unique permissions retained. ]")
    return list(normalized_permissions.values())


def process_permissions(permissions, resources, default_policy="DefaultDenyPolicy"):
    """
    Process permissions and ensure DefaultDenyPolicy is applied for resources without permissions.
    
    Args:
        permissions (list): List of defined permissions in the configuration.
        resources (list): List of all resources with scopes.
        default_policy (str): The default policy to apply for resources without permissions.
        
    Returns:
        list: Processed permissions with DefaultDenyPolicy added for uncovered resources.
    """
    
    print("[ Processing permissions ...]")
    
    # Helper function to normalize resource names
    def normalize(value):
        return value.strip("/")

    # Create a set of normalized resource names with defined permissions
    resources_with_permissions = {normalize(perm["resource"]) for perm in permissions}

    # Iterate through all resources and add DefaultDenyPolicy permissions for uncovered ones
    for resource in resources:
        normalized_resource_name = normalize(resource["name"])
        if normalized_resource_name not in resources_with_permissions:
            # Generate DefaultDenyPolicy permission for the resource
            default_deny_permission = {
                "name": f"DefaultDenyPermission:{normalized_resource_name}",
                "resource": normalized_resource_name,
                "scopes": resource.get("scopes", []),
                "policies": [default_policy],
            }
            print(f"[ Adding DefaultDenyPermission for resource: {normalized_resource_name} ...]")
            permissions.append(default_deny_permission)
            
            # if ENV_NAME == "dev-01":
            #     #NOTE: dev-01 changes for assigning permissions to OrgAdmin and OrgRootAdmin
            #     _permission_for_org_admin = {
            #         "name": f"OrgAdminPermission:{normalized_resource_name}",
            #         "resource": normalized_resource_name,
            #         "scopes": resource.get("scopes", []),
            #         "policies": ["OrgAdminRolePolicy"],
            #     }
            #     _permission_for_org_root_admin = {
            #         "name": f"OrgRootAdminPermission:{normalized_resource_name}",
            #         "resource": normalized_resource_name,
            #         "scopes": resource.get("scopes", []),
            #         "policies": ["OrgRootAdminRolePolicy"],
            #     }
            #     print(f"[ Adding permissions for OrgAdmin and OrgRootAdmin ...]")
            #     permissions.append(_permission_for_org_admin)
            #     permissions.append(_permission_for_org_root_admin)

            #     print(f"    [ Added permissions for OrgAdmin and OrgRootAdmin ENV :: {ENV_NAME} ...]")
            # else:
            #     # Generate DefaultDenyPolicy permission for the resource
            #     default_deny_permission = {
            #         "name": f"DefaultDenyPermission:{normalized_resource_name}",
            #         "resource": normalized_resource_name,
            #         "scopes": resource.get("scopes", []),
            #         "policies": [default_policy],
            #     }
            #     print(f"[ Adding DefaultDenyPermission for resource: {normalized_resource_name} ...]")
            #     permissions.append(default_deny_permission)

    print("[ Permissions processed ...]")
    return permissions


def create_permissions(keycloak_admin: KeycloakAdmin, client_id, permissions, resource_ids, policy_ids):
    """
    Create, update, or delete permissions in Keycloak based on the current configuration.

    Args:
        keycloak_admin (KeycloakAdmin): Keycloak admin client instance.
        client_id (str): Keycloak client ID.
        permissions (list): Processed permissions from the updated configuration.
        resource_ids (dict): Resource ID mapping.
        policy_ids (dict): Policy ID mapping.

    Returns:
        dict: Dictionary of created or existing permission IDs.
    """
    
    def normalize(value):
        """Normalize permission/resource names by stripping leading and trailing slashes."""
        if not value:
            return ""
        # Split the name into prefix and resource parts
        parts = value.split(":", 1)
        # Normalize the resource part (after the colon) by stripping slashes
        if len(parts) > 1:
            return f"{parts[0]}:{parts[1].strip('/')}"
        return value.strip("/")

    # Fetch existing permissions from Keycloak
    permissions_res = keycloak_admin.get_client_authz_permissions(client_id)
    print("Existing Permissions: ", json.dumps(permissions_res, indent=2))
    
    # Build a dictionary of existing permission names for quick lookup
    existing_permissions = {normalize(perm["name"]): perm["id"] for perm in permissions_res}
    print("normalized existing_permissions :: ", json.dumps(existing_permissions, indent=2))
    
    # Build a set of normalized permission names from the updated configuration
    configured_permission_names = {normalize(perm["name"]) for perm in permissions}

    permission_ids = {}

    # Create or update permissions based on the configuration
    for permission in permissions:
        permission_name = normalize(permission["name"])
        resource_name = normalize(permission["resource"])

        # Check if the resource exists before creating the permission
        if resource_name not in resource_ids:
            print(f"    [ Skipping Permission {permission_name}: Resource '{resource_name}' does not exist. ]")
            continue

        # Check if the permission already exists
        if permission_name in existing_permissions:
            print(f"    [ Permission {permission_name} already exists with ID {existing_permissions[permission_name]} ...]")
            permission_ids[permission_name] = {"id": existing_permissions[permission_name]}
            continue

        # Create the permission if it does not exist
        try:
            payload = {
                "name": permission_name,
                "resources": [resource_ids[resource_name]["id"]],
                "type": "scope",
                "scopes": permission["scopes"],
                "policies": [policy_ids[policy]["id"] for policy in permission["policies"]],
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
            }
            response = keycloak_admin.create_client_authz_scope_permission(client_id=client_id, payload=payload)
            permission_ids[permission_name] = response
            print(f"    [ Created Permission: {permission_name} with ID {response['id']} ...]")
        except Exception as e:
            print(f"Error creating permission {permission_name}: {e}")

    # Remove permissions that are no longer defined in the configuration
    for existing_permission_name, existing_permission_id in existing_permissions.items():
        if existing_permission_name not in configured_permission_names:
            try:
                print(f"    [ Removing Permission {existing_permission_name} with ID {existing_permission_id} ...]")
                _res = requests.delete(
                    url=f"{KEYCLOAK_BASE_URL}/admin/realms/{REALM_NAME}/clients/{client_id}/authz/resource-server/permission//scope/{existing_permission_id}",
                    headers={
                        "Authorization": f"Bearer {get_admin_token()}",
                        "content-type": "application/json"
                    }
                )
                print(f"    [ Removed Permission {existing_permission_name} ...]")
            except Exception as e:
                print(f"Error deleting permission {existing_permission_name}: {e}")
    
    print("[ Final permission_ids: ", json.dumps(permission_ids, indent=2), " ... ]")
    print(f"[ Permission processed: {len(permission_ids)} ]")
    return permission_ids


def delete_all_permissions(keycloak_admin: KeycloakAdmin, client_id):
    """
    Deletes all permissions for a given client in Keycloak.
    """
    try:
        # Fetch existing permissions
        permissions_res = keycloak_admin.get_client_authz_permissions(client_id)
        print(f"[ Existing Permissions: {permissions_res} ...]")
        
        # List of permission names to exclude from deletion
        exclusion_list = ["Default Permission"]
        
        # Delete each permission
        for permission in permissions_res:
            permission_id = permission['id']
            permission_name = permission['name']
            
            # Skip permissions in the exclusion list
            if permission_name in exclusion_list:
                print(f"    [ Skipping deletion of permission: '{permission_name}' with ID '{permission_id}' ...]")
                continue
            
            try:
                response = requests.delete(
                    url=f"{KEYCLOAK_BASE_URL}/admin/realms/{REALM_NAME}/clients/{client_id}/authz/resource-server/permission/scope/{permission_id}",
                    headers={
                        'Authorization': f'Bearer {get_admin_token()}',
                        'content-type': 'application/json'
                    }
                )
                
                print(f"    [ Deleted Permission: {permission_name} with ID {permission_id} ...]")
            except Exception as e:
                logger.exception(f"Error deleting permission {permission_name} with ID {permission_id}: {e}")

        print(f"[ Deleted all Existing Permissions ...]")
    except Exception as e:
        logger.exception(f"Error fetching permissions for client {client_id}: {e}")


# Create Permissions
def create_permissions_old(keycloak_admin: KeycloakAdmin, client_id, permissions, resource_ids, policy_ids):
    
    permissions_res = keycloak_admin.get_client_authz_permissions(client_id)
    print("permissions_res: ", permissions_res)
    
    return # i added this return after running this method once 
    
    permission_ids = {}
    for permission in permissions:
        try:
            payload = {
                "name": permission["name"],
                "resources": [resource_ids[permission["resource"]]['_id']],
                "type": "scope",
                "scopes": [scope for scope in permission["scopes"]],
                "policies": [policy_ids[policy]['id'] for policy in permission["policies"]],
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
            }

            response = keycloak_admin.create_client_authz_scope_permission(client_id=client_id, payload=payload)
            permission_ids[permission["name"]] = response
            print(f"Created Permission: {permission['name']} with ID {response}")
        except Exception as e:
            print(e)
            
    print("permission_ids:: ", permission_ids)
    return permission_ids


def update_client_level_auth_setting(realm_name, client_id):
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/clients/{client_id}/authz/resource-server"
    headers={ 'Authorization': f'Bearer {get_admin_token()}', 'content-type': 'application/json' }
    response = requests.get(url, headers=headers)
    
    payload = json.dumps({
        **response.json(),
        'decisionStrategy': 'AFFIRMATIVE'
    })
    
    response = requests.put(url, headers=headers, data=payload)
    response.raise_for_status()
    if response.status_code == 204:
        print("Client auth settings updated successfully")

# Delete by ID
def delete_by_id(keycloak_admin, client_id, delete_type, entity_id):
    if delete_type == "scope":
        keycloak_admin.delete_client_authz_scope(client_id=client_id, scope_id=entity_id)
    elif delete_type == "resource":
        keycloak_admin.delete_client_authz_resource(client_id=client_id, resource_id=entity_id)
    elif delete_type == "policy":
        keycloak_admin.delete_client_authz_policy(client_id=client_id, policy_id=entity_id)
    elif delete_type == "permission":
        keycloak_admin.delete_client_authz_permission(client_id=client_id, permission_id=entity_id)
    print(f"[ Deleted {delete_type} with ID {entity_id} ...]")

# Function to remove preceding and trailing slashes
def clean_name(name):
    return name.strip("/")

# Function to create JSON file from the dictionary
def create_config_file(resource_dict, filename):
    print(f"[ Creating resources config file for realm: {filename} ... ]")
    config_data = []
    id_counter = 1

    # Ensure the config directory exists
    config_dir = os.path.join(os.getcwd(), "config")
    os.makedirs(config_dir, exist_ok=True)

    for path, details in resource_dict.items():
        # Extract and format required fields
        config_entry = {
            "id": details["id"],
            "path": clean_name(path),
            "methods": [scope['name'] for scope in details.get("scopes", [])],
            "name": details["owner"]["name"],
            "description": f"Manage resource at {clean_name(path)}"
        }
        config_data.append(config_entry)
        id_counter += 1

    # Write to a JSON file
    file_path = os.path.join(config_dir, f"{filename}.json")
    with open(file_path, "w") as json_file:
        json.dump(config_data, json_file, indent=2)
    
    print(f"[ Configuration file created at: {file_path} ... ]")

# Main Execution
if __name__ == "__main__":
    # Initialize Keycloak Admin
    keycloak_admin = init_keycloak()

    # Load Configuration
    config = load_config(CONFIG_PATH)
    client_id = keycloak_admin.get_client_id(config["keycloak"]["client"])
    
    # update client level authorization strategy to affirmative 
    update_client_level_auth_setting(REALM_NAME, client_id)

    try:
        # Create Scopes
        scope_ids = create_scopes(keycloak_admin, client_id, config["keycloak"]["scopes"])
    except Exception as e:
        logger.exception(e)
        
    # Create Resources
    try:
        # delete_all_resources(keycloak_admin, client_id)
        resource_ids = create_resources(keycloak_admin, client_id, config["keycloak"]["resources"], scope_ids)
        #TODO: remove print
        # print("RESOURCE_IDS ::: ", resource_ids)
    except Exception as e:
        logger.exception(e)
        
    # create resource id configs(json) in config/
    create_config_file(resource_ids, REALM_NAME)
    
    try:
        # Create Policies
        policy_ids = create_policies(keycloak_admin, client_id, config["keycloak"]["policies"])
        #TODO: remove print
        # print("POLICY_IDS ::: ", policy_ids)
    except Exception as e:
        logger.exception(e)
    
    try:
        # Create Permissions
        # delete_all_permissions(keycloak_admin, client_id)
        # unique_permissions = process_permissions_for_duplicates(config["keycloak"]["permissions"])
        processed_permissions = process_permissions(config["keycloak"]["permissions"], config["keycloak"]["resources"])
        print(" [ Processed_permissions ] :: ", json.dumps(processed_permissions, indent=2))
        permission_ids = create_permissions(keycloak_admin, client_id, processed_permissions, resource_ids, policy_ids)
    except Exception as e:
        logger.exception(e)
        
    # Example: Delete Entities
    # delete_by_id(keycloak_admin, client_id, "scope", scope_ids["GET"])
    # delete_by_id(keycloak_admin, client_id, "resource", resource_ids["Organization Extensions"])
    # delete_by_id(keycloak_admin, client_id, "policy", policy_ids["ViewerRolePolicy"])
    # delete_by_id(keycloak_admin, client_id, "permission", permission_ids["Org Extensions - Viewer"])
