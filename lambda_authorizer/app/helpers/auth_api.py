import base64
import json
import os
import time
import boto3
import requests

from helpers.api_request import APIRequest
from helpers.exceptions import UnauthorizedException, ForbiddenException
from helpers.policy import logger
from helpers.vars import AUTH_API_INTERNAL_ENDPOINT, KEYCLOAK_API_INTERNAL_ENDPOINT
from helpers.vars import SECRET_NAME

current_directory = os.getcwd()

# Global variables for storing the admin token and its expiry
ACCESS_TOKEN_ADMIN = ""
EXPIRY_SECONDS = 0

# Define expiry threshold
EXPIRY_THRESHOLD = 20  # seconds 
# TOKEN VALID FOR 280 second
# 300 is 'expires_in' returned by KC

class AuthAPI:
    def __init__(self, request: APIRequest):
        self.base_url = KEYCLOAK_API_INTERNAL_ENDPOINT
        self.request = request
        self.access_token = request.access_token
        self.token_data = self._get_token_data()
        self.client_id = self._get_client_id()
        self.realm = self._get_realm()
        self.secret_data = self._get_secret()

        self.authz_resource = self._get_authz_resource()

        # Check if secret_data is not None before proceeding
        if self.secret_data:

            self.keycloak_user = self.secret_data.get('KEYCLOAK_ADMIN')
            self.keycloak_password = self.secret_data.get('KEYCLOAK_ADMIN_PASSWORD')
            self.client_data = self.secret_data.get('CLIENT', {}).get(self.client_id)
            self.client_uuid = self.client_data.get('CLIENT_UUID')
            self.client_secret = self.client_data.get('CLIENT_SECRET')

        else:
            logger.error("Failed to initialize AuthAPI: Secret data is missing or invalid.")
            raise UnauthorizedException(f"failed to load credentials")
    def _get_token_data(self):
        if self.request.token_data :
            return self.request.token_data
        else:
            try:
                data = self.request.access_token.split(".")[1]
                data += '=' * (-len(data) % 4)
                data = base64.urlsafe_b64decode(data).decode()
                return json.loads(data)
            except Exception as e:
                logger.exception(f"exception in getting token data {e}")
                raise ForbiddenException
    def introspect_token(self):
        if not self.client_id or not self.client_secret:
            logger.error("Cannot introspect token: Missing client creds.")
            return None

        introspection_result = self._introspect_token()
        if introspection_result.get("active"):
            logger.info(f"Token is active")
            return introspection_result
        logger.info(f"token {self.access_token} is expired")
        return introspection_result

    def check_authorization(self):
        if not self.keycloak_user or not self.keycloak_password:
            logger.error("Cannot authorize user: Missing client creds.")
            return None

        authz_url = f"{self.base_url}/admin/realms/{self.realm}/clients/{self.client_uuid}/authz/resource-server/policy/evaluate"

        def get_admin_token():
            """
            Fetches a new admin token from Keycloak and updates global variables.
            """
            global ACCESS_TOKEN_ADMIN, EXPIRY_SECONDS
            try:
                response = requests.post(
                    f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token",
                    data={
                        "grant_type": "password",
                        "client_id": "admin-cli",
                        "username": self.keycloak_user,
                        "password": self.keycloak_password,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                
                if "error" in response.json():
                    raise UnauthorizedException("Error in getting admin token: get_admin_token")
                
                response.raise_for_status()
                # return response.json().get("access_token")
                token_data = response.json()

                # Update global variables with the new token and expiry
                ACCESS_TOKEN_ADMIN = token_data.get("access_token", "")
                expires_in = token_data.get("expires_in", 300)
                EXPIRY_SECONDS = int(time.time()) + expires_in
            except UnauthorizedException as ue:
                logger.error(f"Error: {str(ue)}")
                raise ue
            except Exception as e:
                logger.exception(f"Unexpected error occured in get_admin_token ::: {str(e)}")
                raise
            
        def get_cached_admin_token():
            """
            Returns a cached admin token or fetches a new one if expired.
            """
            global ACCESS_TOKEN_ADMIN, EXPIRY_SECONDS

            # Check if token is valid and within expiry threshold
            current_time = int(time.time())
            if not ACCESS_TOKEN_ADMIN or EXPIRY_SECONDS - current_time < EXPIRY_THRESHOLD:
                logger.info("Token expired or about to expire. Fetching a new token ...")
                get_admin_token()

            return ACCESS_TOKEN_ADMIN

        headers = {
            'authorization': f'Bearer {get_cached_admin_token()}',
            'content-type': 'application/json',
        }

        auth_payload_attr = self._auth_payload_attr()
        
        # TODO: remove log
        logger.info(f"AUTH_PAYLOAD_ATTR :: {json.dumps(auth_payload_attr)}")
        
        if auth_payload_attr['resource_id'] is None:
            raise UnauthorizedException("Unknown resource")

        payload = {
            "roleIds": [],
            "userId": self.token_data['sub'],
            "resources": [
                {
                    "name": auth_payload_attr['name'],
                    "owner": {
                        "id": self.client_uuid,
                        "name": self.client_id
                    },
                    "ownerManagedAccess": False,
                    "attributes": {},
                    "_id": auth_payload_attr['resource_id'],  # of resoruce
                    "uris": auth_payload_attr['uris'],
                    "scopes": [
                        {
                            "id": self.request.method.upper(),
                            "name": self.request.method.upper()
                        }
                    ]
                }
            ],
            "entitlements": False,
            "context": {
                "attributes": auth_payload_attr['attr']
            }
        }

        response = requests.request("POST", authz_url, headers=headers, data=json.dumps(payload))
        return response.json()
    # def _decode_and_verify_token(self, token):
    #     """
    #     Decode and verify the token using Keycloak's public key.manually
    #     This is kept commented intentionally if needed in future
    #     """
    #     jwks_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/certs"
    #     jwks_response = requests.get(jwks_url).json()
    #
    #     # Get the key ID (kid) from the token header
    #     unverified_header = jwt.get_unverified_header(token)
    #     kid = unverified_header['kid']
    #
    #     # Find the correct key in JWKS
    #     public_key = None
    #     for key in jwks_response['keys']:
    #         if key['kid'] == kid:
    #             public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
    #             break
    #
    #     if not public_key:
    #         raise ValueError("Public key not found for token verification")
    #
    #     # Verify the token
    #     decoded = jwt.decode(
    #         token,
    #         public_key,
    #         algorithms=["RS256"],
    #         audience="empower",  # Replace with your client ID
    #         issuer=f"{self.base_url}/realms/{self.realm}"
    #     )
    #
    #     return decoded

    def _introspect_token(self):
        try:
            
            introspection_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token/introspect"

            data = {
                'token': self.access_token,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            }


            response = requests.post(introspection_url, data=data)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Introspection failed: {response.status_code}", "details": response.text}
        except Exception as e:
            logger.exception(f"Unexpected error occured in _introspect_token :: {str(e)}")
            raise UnauthorizedException("Error in _introspect_token")

    def _get_secret(self):
        """
        Retrieves the client ID and client secret for the organization from AWS Secrets Manager.
        return in format
        {
          "master": {
            "KEYCLOAK_ADMIN": "...",
            "KEYCLOAK_ADMIN_PASSWORD": "..."
          },
          "merumesh": {
            "KEYCLOAK_ADMIN": "...",
            "KEYCLOAK_ADMIN_PASSWORD": "...",
            "CLIENT": {
              "empower": {
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
        client = boto3.client('secretsmanager')

        try:
            # Retrieve the secret
            get_secret_value_response = client.get_secret_value(SecretId=SECRET_NAME)

            secret_data = json.loads(get_secret_value_response['SecretString'])
            logger.info(f"Successfully retrieved secret for {self.realm}")
            return secret_data.get(self.realm)

        except Exception as e:
            logger.error(f"Failed to retrieve secret '{SECRET_NAME}': {str(e)}")
            return None

    def _get_realm(self):
        if self.token_data.get('iss'):
            return self.token_data.get('iss','').split("/")[-1]
        return ''

    def _get_client_id(self):
        if self.token_data.get('client_id',None):
            return self.token_data.get('client_id')
        return self.token_data.get('azp')

    def _match_resource(self, request_path, request_method):
        logger.info(f"Matching resource for path: {request_path} and method: {request_method}")
        
        request_segments = request_path.strip("/").split("/")

        for resource in self.authz_resource:
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
                logger.info(f"Match found for resource: {resource['name']}")
                return {
                    "id": resource["id"],  # Include the resource ID
                    "resource_name": resource["name"],
                    "description": resource["description"],
                    "matched_pattern": resource["path"],  # Include the matched resource pattern
                    "parameters": params,
                }
        
        logger.error(f"No match found for path: {request_path}")
        return None  # No match found

    def get_auth_payload_attr(self):
        try:
            attr =  self._auth_payload_attr()
            return attr.get('attr',{})
        except UnauthorizedException:
            return {'org_id': None}

    def _auth_payload_attr(self):
        matched_resource = self._match_resource(request_path=self.request.path.strip("/"), request_method=self.request.method)
        if matched_resource is None:
            logger.error(f"Resource not found for path: {self.request.path}")
            raise ForbiddenException("Invalid Resource or Method")
        return {
            "name": matched_resource['matched_pattern'],
            "uris": [matched_resource['matched_pattern']],
            "resource_id": matched_resource['id'],
            "attr": matched_resource['parameters']
        }

    def _get_authz_resource(self):
        try:
            data = open(f'{current_directory}/config/{self.realm}.json').read()
            resources = json.loads(data)
            return resources
        except FileNotFoundError:
            # Specific handling for missing file
            logger.error(f"Realm config file not found.")
            raise ForbiddenException(f"Realm config does not exist for: {self.realm}")
        except ForbiddenException as fe:
            raise fe
        except Exception as e:
            logger.exception(f"Unexpected exception in loading resource data: {e}")
            raise ForbiddenException("Error in authorization")
