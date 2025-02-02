import json
import logging

from helpers.api_request import APIRequest
from helpers.authentication import authenticate_request
from helpers.authorization import authorize_request
from helpers.exceptions import UnauthorizedException, ForbiddenException
from helpers.policy import generate_policy
from helpers.vars import ALLOW, DENY, USER

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    request = APIRequest(event)
    try:
        # Log the incoming event
        logger.info("Received event: %s", json.dumps(event))

        if request.method == "OPTIONS":
            return generate_policy(USER, ALLOW, request.method_arn, request.event_version)

        # Authenticate the request
        is_authenticated = False
        token_data = {}
        try:
            is_authenticated, token_data = authenticate_request(request)
        except ForbiddenException as fe:
            logger.error("Forbidden error: %s", str(fe))
            raise fe
        except UnauthorizedException as ue:
            logger.error("Unauthorized error: %s", str(ue))
            raise ue
        except Exception as e:
            logger.error("Unexpected error: %s", str(e))
            raise UnauthorizedException("User Not authenticated.")
            # return generate_policy(USER, DENY, request.method_arn, request.event_version)

        if token_data is None:
            return generate_policy(USER, ALLOW, request.method_arn, request.event_version)

        if not is_authenticated:
            raise UnauthorizedException("User Not authenticated.") # Results to 401
        
        ###
        request.token_data = token_data

        is_authorized = authorize_request(request)

        if not is_authorized:
            raise ForbiddenException("User Not Authorized")
        ###

        return generate_policy(USER, ALLOW, request.method_arn, request.event_version, token_data)

    except UnauthorizedException as ue:
        logger.error("Unauthorized error: %s", str(ue))
        raise Exception("Unauthorized")  # Will return 401 Unauthorized

    except ForbiddenException as fe:
        logger.error("Forbidden error: %s", str(fe))
        return generate_policy(USER, DENY, request.method_arn, request.event_version)

    except Exception as e:
        logger.error("Unexpected error: %s", str(e))
        return generate_policy(USER, DENY, request.method_arn, request.event_version)