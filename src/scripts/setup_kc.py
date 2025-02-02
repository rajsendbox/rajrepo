import argparse
import os
import logging
import requests
import random
import string
import boto3
import json

from dotenv import load_dotenv
from keycloak import KeycloakAdmin

load_dotenv()

"""
TODO:
get config from setup_kc_config.yaml
"""

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

# Replace these values with your Keycloak setup
KEYCLOAK_BASE_URL = os.getenv('KEYCLOAK_BASE_URL', "http://localhost:8080")
# TODO get from secret manager adn get secret_name form env
SECRET_NAME = os.getenv('MASTER_REALM_SECRET_NAME', 'keyclock/admin/creds')
AWS_REGION = os.getenv("AWS_REGION", "us-west-2")
LOCAL_URI = "http://localhost:3000"
LOCAL_REDIRECT_URI = "http://localhost:3000/*"

# Set this flag to True to always use default credentials
USE_DEFAULT_CREDENTIALS = os.getenv("USE_DEFAULT_CREDENTIALS", "False").lower() == "true"

# print("os.getenv(" ,os.getenv("USE_DEFAULT_CREDENTIALS"))
print("USE_DEFAULT_CREDENTIALS", USE_DEFAULT_CREDENTIALS)

# MASTER_REALM_ADMIN_USERNAME = "admin"
# MASTER_REALM_ADMIN_PASSWORD = "password"

CLIENT_ID = "admin-cli"

# Configuration for multiple realms
REALM_CONFIG = [
    # {"realm_name": "merumesh", "admin_username": "merumesh-admin"},
    {"realm_name": "identra", "admin_username": "identra-admin"},
    {"realm_name": "merumesh-authz", "admin_username": "merumesh-admin-authz"},
    # {"realm_name": "merumesh-sandbox", "admin_username": "merumesh-sandbox-admin"}
]

# List of groups to create in each realm
GROUPS_TO_CREATE = ["analyst", "browser-extension-user",
                    "customer-org-admin", "customer-org-root-admin",
                    "deployment-admin", "viewer"]

GROUP_TO_ROLE_MAP = {
    "analyst" :"client-role-analyst",
    "browser-extension-user":"client-role-browser-extension-user",
    "viewer":"client-role-viewer",
    "customer-org-admin": "client-role-org-admin",
    "customer-org-root-admin": "client-role-org-root-admin",
    "deployment-admin": "client-role-deployment-admin",
}

# TODO get from env
# Client configuration
CLIENT_NAME = os.getenv('CLIENT_NAME', "empower")
CLIENT_ROOT_URL = os.getenv('EMPOWER_BASE_URL', "http://localhost:3001")
CLIENT_HOME_URL = f"{CLIENT_ROOT_URL}/home"
CLIENT_REDIRECT_URI = f"{CLIENT_ROOT_URL}/auth/v3"
CLIENT_REDIRECT_URI_LOCAL = f"http://localhost:3001/auth/v3"
CLIENT_REDIRECT_URI_LIST = [CLIENT_REDIRECT_URI, CLIENT_REDIRECT_URI_LOCAL]
WEB_ORIGINS=[CLIENT_ROOT_URL]


# Initialize Keycloak Admin
def init_keycloak(realm):
    return KeycloakAdmin(
        server_url=KEYCLOAK_BASE_URL,
        username=MASTER_REALM_ADMIN_USERNAME,
        password=MASTER_REALM_ADMIN_PASSWORD,
        realm_name=realm,
        user_realm_name="master"
    )

# Fetch master realm credentials
def get_master_realm_credentials():
    if USE_DEFAULT_CREDENTIALS:
        print("[ Using default credentials as per configuration ... ]")
        return "admin", "password"

    secret_values = get_secret_from_secret_managaer(SECRET_NAME, AWS_REGION)

    if not secret_values or "master" not in secret_values:
        print("[ 'master' key not found in Secrets Manager, using default credentials ... ]")
        return "admin", "password"

    master_credentials = secret_values["master"]
    username = master_credentials.get("KEYCLOAK_ADMIN", "admin")
    password = master_credentials.get("KEYCLOAK_ADMIN_PASSWORD", "password")

    print("[ Successfully fetched master realm credentials from Secrets Manager ... ]")
    return username, password

def init_master_admin_creds():
    global MASTER_REALM_ADMIN_USERNAME, MASTER_REALM_ADMIN_PASSWORD

    # Refresh credentials from Secrets Manager or use default
    MASTER_REALM_ADMIN_USERNAME, MASTER_REALM_ADMIN_PASSWORD = get_master_realm_credentials()
    
# Step 1: Authenticate as the master realm admin
def get_master_realm_token():
    print("[ Getting master_token ... ]")
    url = f"{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token"
    payload = {
        'client_id': CLIENT_ID,
        'username': MASTER_REALM_ADMIN_USERNAME,
        'password': MASTER_REALM_ADMIN_PASSWORD,
        'grant_type': 'password'
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url, data=payload, headers=headers)
    response.raise_for_status()
    return response.json()['access_token']

# Step 2: Create a new realm
def create_realm(access_token, realm_name):
    print(f"[ Creating Realm: {realm_name} ... ]")
    url = f"{KEYCLOAK_BASE_URL}/admin/realms"
    payload = {
        "realm": realm_name,
        "enabled": True,
        # "unmanagedAttributePolicy": "ENABLED"
    }
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 409:
        print(f"[ Realm: {realm_name} already exists ...]")
        
    if response.status_code == 201:
        print(f"[ Realm: {realm_name} created ...]")
        
        # Unassign all default roles except uma_authorization
        unassign_default_roles(access_token, realm_name)
        
    if response.status_code not in [201, 409]:
        response.raise_for_status()


# Step 3: Create a user in the new realm
def create_user_in_realm(access_token, realm_name, username):
    print(f"[ Checking if user '{username}' exists in realm '{realm_name}' ... ]")
    search_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/users?username={username}"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Check if user exists
    response = requests.get(search_url, headers=headers)
    if response.status_code != 200:
        print("Error while searching for user:", response.text)
        return None

    users = response.json()
    if any(user['username'].lower() == username.lower() for user in users):
        print(f"[ User '{username}' already exists. ]")
        return None

    # Create the user if not found
    print(f"[ Creating user '{username}' in realm '{realm_name}' ... ]")
    create_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/users"
    
    # Generate a random password for the admin user
    password = generate_random_password()
    
    payload = {
        "username": username,
        "enabled": True,
        "emailVerified": True,
        "email": f"admin@{realm_name}.com",
        "firstName": realm_name,
        "lastName": "admin",
        "credentials": [{
            "type": "password",
            "value": password,
            "temporary": False
        }]
    }

    create_response = requests.post(create_url, headers=headers, json=payload)
    if create_response.status_code == 201:
        print(f"User '{username}' created successfully.")
        return {
            realm_name: {
                "KEYCLOAK_ADMIN": username,
                "KEYCLOAK_ADMIN_PASSWORD": password
            }
        }
    else:
        print("Error creating user:", create_response.text)
        return None


def assign_realm_admin_role(access_token, realm_name, username):
    print(f"[ Checking if user '{username}' already has the 'realm-admin' role in realm '{realm_name}' ]")

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Step 1: Get user ID
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/users?username={username}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    
    user_data = response.json()
    if not user_data:
        print(f"[ User '{username}' not found in realm '{realm_name}'. ]")
        return

    user_id = user_data[0]['id']
    print(f"[ User ID: {user_id} ]")

    # Step 2: Check if the user already has the 'realm-admin' role
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/users/{user_id}/role-mappings"
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    role_mappings = response.json()

    # Check if 'realm-admin' exists in the client mappings
    client_roles = role_mappings.get("clientMappings", {}).get("realm-management", {}).get("mappings", [])
    has_realm_admin = any(role['name'] == 'realm-admin' for role in client_roles)

    if has_realm_admin:
        print(f"[ User '{username}' already has the 'realm-admin' role ...]")
        return

    print(f"[ User '{username}' does not have the 'realm-admin' role. Assigning the role ...]")

    # Step 3: Get available roles for assignment
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/ui-ext/available-roles/users/{user_id}?first=0&max=50&search=realm-management"
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    # roles_response = response.json()

    # Find the 'realm-admin' role from available roles
    admin_role = next((role for role in response.json() if role['role'] == 'realm-admin'), None)
    if not admin_role:
        print("[ X | Error: 'realm-admin' role not found ...]")
        return


    # Step 4: Assign the role
    payload = [{
        "id": admin_role['id'],
        "name": admin_role['role'],
        "description": admin_role.get('description', '')
    }]

    client_id = admin_role['clientId']
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/{client_id}"

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 204:
        print(f"[ Successfully assigned the 'realm-admin' role to user '{username}' ...]")
    else:
        print(f"[ X | Failed to assign role. Status Code: {response.status_code}, Response: {response.text} ...]")

# # Step 4: Assign admin role to the user
# def assign_realm_admin_role(access_token, realm_name, username, realm_id):
#
#     # Get user ID
#     url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/users?username={username}"
#     headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
#
#     response = requests.get(url, headers=headers)
#     response.raise_for_status()
#     user_id = response.json()[0]['id']
#
#     # Get admin role ID
#     url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/ui-ext/available-roles/users/{user_id}?first=0&max=50&search=realm-management"
#     response = requests.get(url, headers=headers)
#     response.raise_for_status()
#
#     resp_json = response.json()
#     client_id = resp_json[0]['clientId']
#
#     payload = [{
#         "name":admin_role['role'],
#         "id": admin_role['id'],
#         "description": admin_role['description']
#     } for admin_role in resp_json]
#
#
#     url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/{client_id}/"
#     response =  requests.post(url, headers={'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'},json=payload)
#     print(response)

# Step 5: Unassign default roles except uma_authorization
def unassign_default_roles(access_token, realm_name):
    print(f"[ Starting unassign default roles process for Realm: {realm_name} ...]")
    
    # Get the ID of the default-roles-{realm} role
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/roles"
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    default_roles = next((role for role in response.json() if role['name'] == f"default-roles-{realm_name}"), None)

    if not default_roles:
        raise Exception(f"Default roles not found for realm {realm_name}")

    default_role_id = default_roles['id']

    # Get composite roles of the default-roles-{realm}
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/roles-by-id/{default_role_id}/composites"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    composite_roles = response.json()

    # Filter out the roles to remove (all except uma_authorization)
    roles_to_remove = [role for role in composite_roles if role['name'] != 'uma_authorization']

    if roles_to_remove:
        # Remove the roles
        url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/roles-by-id/{default_role_id}/composites"
        response = requests.delete(url, headers=headers, json=roles_to_remove)
        response.raise_for_status()


# Step 6: Create groups in the realm
def create_groups_in_realm(access_token, realm_name):
    print(f"[ Creating groups in realm: {realm_name} ...]")
    
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/groups"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    for group in GROUPS_TO_CREATE:
        payload = {"name": group}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 409:
            print(f"[ Group: {group} already exists for Realm: {realm_name} ...]")
            
        if response.status_code == 201:
            print(f"[ Group: {group} created for Realm: {realm_name} ...]")
                
        if response.status_code not in [201, 409]:  # 201 means created, 409 means conflict (already exists)
            response.raise_for_status()


def assign_default_group_to_realm(access_token, realm_name):
    print(f"[ Checking and assigning default group 'browser-extension-user' in realm: {realm_name} ]")
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Step 1: Get current default groups
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/default-groups"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    default_groups = response.json()

    # Check if the group is already a default group
    for group in default_groups:
        if group['name'] == 'browser-extension-user':
            print("[ Group 'browser-extension-user' is already a default group. ]")
            return

    # Step 2: Get the group ID by name
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/groups"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    all_groups = response.json()

    group_id = next((group['id'] for group in all_groups if group['name'] == 'browser-extension-user'), None)

    if not group_id:
        print("[ X | Error: Group 'browser-extension-user' not found. ]")
        return

    # Step 3: Add the group to default groups
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/default-groups/{group_id}"
    response = requests.put(url, headers=headers)
    
    if response.status_code == 204:
        print("[ Successfully assigned 'browser-extension-user' as a default group. ]")
    else:
        print(f"[ Failed to assign default group. Status code: {response.status_code}, Response: {response.text} ]")

def assign_default_role_to_realm(realm_name):
    admin = init_keycloak(realm_name)
    print(f"[ Initializing Keycloak for realm: {realm_name} ]")
    
    roles = admin.get_realm_roles()
    print(f"[ Fetched {len(roles)} roles from realm '{realm_name}' ...]")

    # Find the 'offline_access' role
    offline_access_role = next((role for role in roles if role['name'] == 'offline_access'), None)
    
    if offline_access_role:
        print(f"[ Found role: {offline_access_role['name']} with ID: {offline_access_role['id']} ... ]")
        
        # Prepare payload and assign the role
        payload = [offline_access_role]
        admin.add_realm_default_roles(payload)
        print(f"[ Successfully assigned the 'offline_access' role as a default role in realm '{realm_name}' ... ]")
    else:
        print(f"[ X | Role 'offline_access' not found in realm '{realm_name}'. No roles assigned ...]")
    
    
def update_realm_otp_policy(access_token, realm_name):
    print(f"[ Updating realm otp policy for realm: {realm_name} ...]")
    
    # get realm
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}"
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    realm = response.json()
    
    # otp policy configs
    # NOTE: keeping default OTP policy (for Authenticator)
    
    # realm["otpPolicyPeriod"] = 60
    # realm["otpPolicyDigits"] = 8
    # realm["otpPolicyAlgorithm"] = "HmacSHA256"
    
    # password policy
    realm["passwordPolicy"] = "notContainsUsername(undefined) and upperCase(1) and lowerCase(1) and length(8) and notEmail(undefined) and specialChars(1)"
    
    # update realm
    response = requests.put(url, headers=headers, json=realm)
    response.raise_for_status()
    
    if response.status_code == 204:
        print(f"[ Successfully updated Realm OTP policy for realm: {realm_name} ...]")
    else:
        print(f"[ X | Something went wrong while updating realm otp policy for realm: {realm_name}. Status: {response.status_code} ...]")
        
        
def get_client_secret(realm_name, client_id):
    """
    Fetches the client secret from Keycloak.
    """
    admin = init_keycloak(realm_name)
    
    client_secret = admin.get_client_secrets(client_id)
    
    return client_secret.get("value")
    

# Step 7: Create a client in the realm
def create_client_in_realm(access_token, realm_name):
    print(f"[ Checking if client exists in realm: {realm_name} ...]")
    
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/clients"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    # Check if the client already exists
    response = requests.get(url, headers=headers, params={"clientId": CLIENT_NAME})
    response.raise_for_status()
    existing_clients = response.json()
    
    if existing_clients:
        client_id = existing_clients[0]['id']
        print(f"[ Client '{CLIENT_NAME}' already exists with ID: {client_id} ...]")
        return None
    
    print(f"[ Creating client '{CLIENT_NAME}' in realm: {realm_name} ...]")
    
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/clients"
    payload = {
          "protocol": "openid-connect",
          "clientId": "empower",
          "name": "empower",
          "description": "",
          "publicClient": False,
          "authorizationServicesEnabled": True,
          "serviceAccountsEnabled": True,
          "implicitFlowEnabled": True,
          "directAccessGrantsEnabled": True,
          "standardFlowEnabled": True,
          "frontchannelLogout": True,
          "attributes": {
            "access.token.lifespan": 1800,
            "client.session.idle.timeout": 28800,
            "client.session.max.lifespan": 28800,
            "client.offline.session.idle.timeout": 36000,
            "saml_idp_initiated_sso_url_name": "",
            "oauth2.device.authorization.grant.enabled": False,
            "oidc.ciba.grant.enabled": False
          },
          "alwaysDisplayInConsole": False,
          "rootUrl": CLIENT_ROOT_URL,
          "baseUrl": CLIENT_HOME_URL,
          "redirectUris": CLIENT_REDIRECT_URI_LIST,
          "webOrigins": WEB_ORIGINS
        }
    if env == 'dev-01':
        payload['redirectUris'].append(LOCAL_REDIRECT_URI)
        payload['webOrigins'].append(LOCAL_URI)
    access_token = get_master_realm_token()
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()

    # Retrieve the client ID
    response = requests.get(url, headers=headers, params={"clientId": CLIENT_NAME})
    response.raise_for_status()
    client_id = response.json()[0]['id']
    print(f"[ Created Client '{CLIENT_NAME}' with ID: {client_id} ...]")

    # Create client roles corresponding to groups
    create_client_roles(access_token, realm_name, client_id)

    # Set client scopes
    set_client_scopes(access_token, realm_name, client_id)

    # Map roles to groups
    map_roles_to_groups(access_token, realm_name, client_id)
    
    client_secret = get_client_secret(realm_name, client_id)
    
    # TODO: CLIENT_ID: from config
    return {
        "empower": {
            "CLIENT_ID": "empower",
            "CLIENT_UUID": client_id,
            "CLIENT_SECRET": client_secret
        }
    }
    
    
# Step 8: Create client roles
def create_client_roles(access_token, realm_name, client_id):
    print(f"[ Creating client roles in realm: {realm_name} ...]")
    
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/clients/{client_id}/roles"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    for group in GROUPS_TO_CREATE:
        payload = {"name": GROUP_TO_ROLE_MAP[group]}
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code not in [201, 409]:
            response.raise_for_status()

# Step 9: Set client scopes
def set_client_scopes(access_token, realm_name, client_id):
    print(f"[ Updating organization client scopes for realm: {realm_name}, client: {client_id} ...]")
    # delete client organization scope from optional-scopes and
    # put client organization scope in default-scopes

    admin = init_keycloak(realm_name)
    
    client_scope = admin.get_client_scope_by_name('organization')
    org_client_scope_id = client_scope['id']
    
    admin.delete_default_optional_client_scope(org_client_scope_id)
    admin.add_default_default_client_scope(org_client_scope_id)

    admin.delete_client_optional_client_scope(client_id, org_client_scope_id)
    payload = {
        "realm": realm_name,
        "client": client_id,
        "clientScopeId": org_client_scope_id
    }
    admin.add_client_default_client_scope(client_id, org_client_scope_id, payload)


# Step 10: Enable client authorization settings
def enable_client_authorization(access_token, realm_name, client_id):
    print(f"[ Enabling client authorization for realm: {realm_name}, client_id: {client_id} ...]")
    
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/clients/{client_id}"
    headers = { 
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    payload = {
        "authorizationSettings": {
            "policyEnforcementMode": "ENFORCING",
            "allowRemoteResourceManagement": True
        }
    }
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()

# Step 11: Map roles to groups
def map_roles_to_groups(access_token, realm_name, client_id):
    print(f"[ Mapping roles to groups for realm: {realm_name}, client: {client_id} ...]")
    
    # Retrieve the roles of the client
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/clients/{client_id}/roles"
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    roles = response.json()

    # Map each group to a corresponding role
    for group in GROUPS_TO_CREATE:
        print(f"   - [ Mapping role for group: {group} ...]")
        
        role = next((r for r in roles if r['name'] == GROUP_TO_ROLE_MAP[group]), None)
        if role:
            group_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/groups?search={group}"
            response = requests.get(group_url, headers=headers)
            response.raise_for_status()
            group_id = response.json()[0]['id']

            role_mapping_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/groups/{group_id}/role-mappings/clients/{client_id}"
            payload = [role]
            response = requests.post(role_mapping_url, headers=headers, json=payload)
            response.raise_for_status()

# Step 12: Set default roles for groups
def set_default_group_roles(access_token, realm_name):
    print(f"[ Seetting default group roles for realm: {realm_name} ...]")
    
    url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/groups"
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    groups = response.json()

    for group in groups:
        print(f"   - [ Processing group: {group['name']} ...]")
        
        group_id = group['id']
        group_roles_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{realm_name}/groups/{group_id}/role-mappings/realm"
        payload = [{"name": group['name']}]
        response = requests.post(group_roles_url, headers=headers, json=payload)
        if response.status_code not in [201, 409]:
            response.raise_for_status()

# Generate a random password
def generate_random_password():
    print(f"[ Generating password ...]")
    
    # Define character pools
    special_characters = '!#$*+?@^_'
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    
    # Ensure at least one character from each required pool
    password = [
        random.choice(special_characters),
        random.choice(uppercase_letters),
        random.choice(lowercase_letters),
        random.choice(digits)
    ]
    
    # Determine the length (randomly between 8 and 12)
    length = random.randint(8, 12)
    
    # Fill the rest of the password with random characters
    all_characters = special_characters + uppercase_letters + lowercase_letters + digits
    password += [random.choice(all_characters) for _ in range(length - len(password))]
    
    # Shuffle to randomize the order
    random.shuffle(password)
    
    return ''.join(password)


def save_creds_in_secret_manager(realm_admin_creds, realm_client_details_and_creds):
    """
    # get get_secret_from_secret_managaer
    # build secret_value to write in secret managaer 
    
    # realm_admin_creds
    {'merumesh': {'KEYCLOAK_ADMIN': 'merumesh-admin', 'KEYCLOAK_ADMIN_PASSWORD': '...'}}
    
    # realm_client_details_and_creds
    {'empower': {'CLIENT_ID': 'empower', 'CLIENT_UUID': 'UUID', 'CLIENT_SECRET': '...'}}
    
    # final secret_value structure
    secret_value = {
        "master": {
            "KEYCLOAK_ADMIN": "admin",
            "KEYCLOAK_ADMIN_PASSWORD": "..."
        },
        "merumesh": {
            "KEYCLOAK_ADMIN": "...",
            "KEYCLOAK_ADMIN_PASSWORD": "...",
            "CLIENT": {      
                "empower": { 
                    "CLIENT_ID: "empower",       
                    "CLIENT_UUID": "...",        
                    "CLIENT_SECRET": "..."      
                }
            }
        },
        "merumesh-production": {    
            "KEYCLOAK_ADMIN": "...",    
            "KEYCLOAK_ADMIN_PASSWORD": "...",   
            "CLIENT": {      
                "empower": {        
                    "CLIENT_UUID": "...",        
                    "CLIENT_SECRET": "..."      
                }    
            }  
        }
    }
    """
    if USE_DEFAULT_CREDENTIALS:
        print("realm_admin_creds: :", realm_admin_creds)
        print("realm_client_details: :", realm_client_details)
        print("   - [ Alert: using Local Environment - Skipping writing creds in secret manager ...]")
        
        return
    
    # Ensure both inputs are not None
    if not realm_admin_creds:
        print("Alert: realm_admin_creds is None. Cannot proceed to save_creds_in_secret_manager.")
        return

    if not realm_client_details_and_creds:
        print("Alert: realm_client_details_and_creds is None. Cannot proceed to save_creds_in_secret_manager.")
        return

    # Fetch existing secrets from Secrets Manager
    current_secrets = get_secret_from_secret_managaer(SECRET_NAME, AWS_REGION)
    
    # TODO: what if current_secrets is None ??
    if not current_secrets:
        # If no secret exists, initialize a new structure
        current_secrets = {
            "master": {
                "KEYCLOAK_ADMIN": "admin",
                "KEYCLOAK_ADMIN_PASSWORD": ""
            }
        }
   

    # Extract realm and update values
    realm_name = list(realm_admin_creds.keys())[0]
    current_secrets[realm_name] = {
        **realm_admin_creds[realm_name],  # Add admin credentials
        "CLIENT": realm_client_details_and_creds
    }
    # print("current_secrets: ", current_secrets)
    write_secret_in_secret_manager(SECRET_NAME, current_secrets, AWS_REGION)
    

def get_secret_from_secret_managaer(secret_name, region_name):
    """
    Fetch a secret from AWS Secrets Manager with detailed error logging.

    :param secret_name: Name of the secret in AWS Secrets Manager
    :param region_name: AWS Region where the secret is stored
    :return: Secret value as a dictionary
    """
    try:
        session = boto3.session.Session()
        client = session.client(service_name="secretsmanager", region_name=region_name)

        print(f"Fetching secret '{secret_name}' from region '{region_name}'...")

        response = client.get_secret_value(SecretId=secret_name)

        if 'SecretString' in response:
            secret = json.loads(response['SecretString'])
        else:
            secret = response['SecretBinary']

        print("Secret fetched successfully.")
        return secret

    except client.exceptions.ResourceNotFoundException:
        print(f"Error: Secret '{secret_name}' not found in region '{region_name}'.")
    except client.exceptions.InvalidRequestException as e:
        print(f"Invalid request: {e}")
    except client.exceptions.AccessDeniedException:
        print("Access denied. Check your IAM permissions.")
    except Exception as e:
        print(f"Unexpected error: {e}")

    return None


def write_secret_in_secret_manager(secret_name, secret_value, region_name):
    """
    Write a secret to AWS Secrets Manager.

    :param secret_name: Name of the secret
    :param secret_value: Dictionary containing the secret data
    :param region_name: AWS Region
    :return: Response from AWS Secrets Manager
    """
    try:
        # Create a session
        session = boto3.session.Session()

        # Create a Secrets Manager client
        client = session.client(
            service_name="secretsmanager",
            region_name=region_name
        )

        # Check if secret already exists
        try:
            client.describe_secret(SecretId=secret_name)
            # Update secret if it already exists
            response = client.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(secret_value)
            )
            print(f"Secret '{secret_name}' updated successfully.")
        except client.exceptions.ResourceNotFoundException:
            # Create secret if it doesn't exist
            response = client.create_secret(
                Name=secret_name,
                SecretString=json.dumps(secret_value)
            )
            print(f"Secret '{secret_name}' created successfully.")

        return response

    except client.exceptions.InvalidRequestException as e:
        print(f"Invalid request: {e}")
    except client.exceptions.AccessDeniedException:
        print("Access denied. Check your IAM permissions.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def configure_realm_required_actions(realm_name: str):
    
    print(f"[ Configuring Required Actions for realm: {realm_name} ]")
    
    admin = init_keycloak(realm=realm_name)
    
    action_alias = "CONFIGURE_TOTP"
    
    payload = {
        "alias": "CONFIGURE_TOTP",
        "name": "Configure OTP",
        "providerId": "CONFIGURE_TOTP",
        "enabled": True,
        "defaultAction": False,
        "priority": 10,
        "config": {}
    }
    
    admin.update_required_action(action_alias, payload)
    

def _update_realm(master_access_token, realm_name):
    admin = init_keycloak(realm_name)
    
    realm = admin.get_realm(realm_name=realm_name)
    
    # updates
    realm["organizationsEnabled"] = True
    realm["bruteForceProtected"] = True
    realm["failureFactor"] = 10
    realm[ "minimumQuickLoginWaitSeconds"] = 300
    
    admin.update_realm(realm_name=realm_name, payload=realm)
    

# Main script execution
if __name__ == "__main__":
    try:
        # Authenticate with master realm admin credentials

        # Dictionary to store generated credentials
        credentials = {}
        parser = argparse.ArgumentParser(description="Fetch secrets from AWS Secrets Manager")
        parser.add_argument('--env', required=True, help="Environment name (e.g., dev, prod)", default='default')
        args = parser.parse_args()
        env = args.env
        init_master_admin_creds()

        for realm in REALM_CONFIG:
            realm_name = realm["realm_name"]
            admin_username = realm["admin_username"]
            

            # Create the realm
            master_token = get_master_realm_token()
            create_realm(master_token, realm_name)
            
            
            master_token = get_master_realm_token()
            _update_realm(master_token, realm_name)
            
            
            configure_realm_required_actions(realm_name)
            
            
            master_token = get_master_realm_token()
            update_realm_otp_policy(master_token, realm_name)
            

            # Create the realm-specific admin user
            master_token = get_master_realm_token()
            realm_admin_creds = create_user_in_realm(master_token, realm_name, admin_username)
            
            
            # Create groups in the realm
            master_token = get_master_realm_token()
            create_groups_in_realm(master_token, realm_name)
            
            # assign default group to realm
            master_token = get_master_realm_token()
            assign_default_group_to_realm(master_token, realm_name)
            
            # assign default roles to realm (offline_access)
            assign_default_role_to_realm(realm_name)
            
            # Create a client in the realm
            master_token = get_master_realm_token()
            realm_client_details = create_client_in_realm(master_token, realm_name) 
            
            # exit(0)

            # Assign the realm-admin role to the user
            master_token = get_master_realm_token()
            assign_realm_admin_role(master_token, realm_name, admin_username) 
            
            
            save_creds_in_secret_manager(realm_admin_creds, realm_client_details)
            
            # print("realm_admin_creds: :", realm_admin_creds)
            # print("realm_client_details: :", realm_client_details)
            

    except Exception as e:
        logger.exception(f"An error occurred: {e}")
