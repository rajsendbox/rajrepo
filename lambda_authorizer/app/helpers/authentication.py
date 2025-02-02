import json
import logging

from helpers.exceptions import UnauthorizedException, ForbiddenException
from helpers.api_request import APIRequest
from helpers.auth_api import AuthAPI
from helpers.vars import AUTHENTICATION_EXCLUDED_PATHS

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def authenticate_request(request: APIRequest):
    """
    Authenticates the incoming request based on the authorization header and checks if the path is excluded.

    Args:
        event (dict): The event data from the request, including headers and path.
        method_arn (str): The ARN of the method being accessed.

    Returns:
        dict: A generated policy allowing or denying access.

    Raises:
        UnauthorizedException: If the authorization header is missing or invalid.
        ForbiddenException: If the user is not authorized to perform the requested action.
    """
    try:
        print("METHOD :: ", request.method)
        print("PATH :: ", request.path)
        print("METHOD_ARN :: ", request.method_arn)
        
        # public endpoints
        if request.path in AUTHENTICATION_EXCLUDED_PATHS:
            logger.info("Path '%s' is excluded from authentication.", request.path)
            return True, None

        # Check for Authorization header
        auth_header = request.auth_header

        if not auth_header or not auth_header.startswith('Bearer '):
            logger.error("Authorization header is missing or invalid.")
            raise UnauthorizedException("Authorization header is missing or invalid")

        access_token = auth_header.split(' ')[1]
        logger.info("Extracted access token.")
        request.access_token = access_token

        # Token introspection
        auth_API = AuthAPI(request)
        introspection_data = auth_API.introspect_token()

        if introspection_data and introspection_data.get('active', False):
            introspection_data['org_id'] = auth_API.get_auth_payload_attr().get('org_id')
            introspection_data['email'] = introspection_data.get('email', '')
            introspection_data['user_id'] = introspection_data.get('sub', '')
            introspection_data['user_name'] = introspection_data.get('username', '')
            introspection_data['organizations'] = json.dumps(introspection_data.get('organizations', []))
            introspection_data['source'] = "keycloak"
            introspection_data['realm'] = auth_API.realm
            introspection_data['session_id'] = introspection_data.get('sid', '')
            
            # Extract and set roles based on 'client_id'
            if 'client_id' in introspection_data:
                client_id = introspection_data['client_id']
                resource_access = introspection_data.get('resource_access', {})
                
                # Get roles from resource_access for the client_id, or set an empty list if not found
                roles = resource_access.get(client_id, {}).get('roles', [])
                
                # Store the roles as a JSON string in introspection_data['roles']
                introspection_data['roles'] = json.dumps(roles)
            else:
                # Set roles to an empty JSON array if 'client_id' is missing
                introspection_data['roles'] = json.dumps([])

            logger.info("Token is valid and active. keycloak data")
            logger.info(introspection_data)
            return True, introspection_data

        else:
            logger.error("Token is expired or invalid.")
            raise UnauthorizedException('Token is expired or invalid')

    except UnauthorizedException as ue:
        logger.error(f"Unauthorized access attempt: {str(ue)}")
        raise ue

    except ForbiddenException as fe:
        logger.error(f"Forbidden action attempt: {str(fe)}")
        raise fe

    except Exception as e:
        logger.error(f"Error during authentication: {str(e)}")
        raise UnauthorizedException("An error occurred during authentication")
