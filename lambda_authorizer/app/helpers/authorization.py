import logging

from helpers.api_request import APIRequest
from helpers.auth_api import AuthAPI
from helpers.exceptions import ForbiddenException, UnauthorizedException
from helpers.vars import AUTHORIZATION_EXCLUDED_PATHS

import json
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def authorize_request(request: APIRequest):
    """
    Authorizes the incoming request based on the user's permissions.

    Args:
        event (dict): The Lambda event object containing the request data.
        access_token (str): The access token of the user.
        user_info (dict): The user information object containing details like user name and org ID.

    Returns:
        bool: True if the user is authorized, False otherwise.
    """
    try:
        path = request.path
        method = request.method
        
        print(f"PATH: '{path}'")
        print(f"method: '{method}'")
        
        if path in AUTHORIZATION_EXCLUDED_PATHS:
            logger.info(f"path {path} is AuhtZ excluded")
            return True
        api = AuthAPI(request)
        authorization = api.check_authorization()
        
        # TODO: remove log
        # logger.info(f"AUTHORIZATION :: {json.dumps(authorization)}")
        
        if authorization and authorization.get('status', '') == "PERMIT":
            logger.info(
                f"Authorization successful for user: {authorization.get('rpt', {}).get('upn', '')} for resource: [{method}]:{path}")
            return True
        else:
            user = authorization.get('rpt', {}).get('preferred_username', '') if authorization and authorization.get('rpt') else authorization
            logger.info(f"Authorization failed for user: {user} for resource: [{method}]:{path}")

        logger.warning(f"Authorization failed for user: {user}, no valid permissions found.")
        return False
    
    except UnauthorizedException as ue:
        raise ue
    except ForbiddenException as fe:
        raise fe
    except Exception as e:
        logger.exception(f"Exception occurred during authorization: {str(e)}")
        return False
