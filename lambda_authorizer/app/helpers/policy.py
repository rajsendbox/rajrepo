import json
import logging

from helpers.vars import USER, DENY

logger = logging.getLogger(__name__)

# NOTE: REST ApiGateway expected json string
def flatten_lists(obj):
    """
    Recursively traverses an object (dictionary) and converts all lists into comma-separated strings.
    If a key's value is a nested dictionary, it processes it recursively.

    Args:
        obj (dict): The dictionary object to process.

    Returns:
        dict: The modified dictionary with lists converted to comma-separated strings.
    """
    for key, value in obj.items():
        if isinstance(value, list|dict):
            # Convert list to comma-separated string
            obj[key] = json.dumps(value)
    return obj

def generate_policy(principal_id=USER, effect=DENY, method_arn="", event_version="2.0", context=None):
    """
    Generates a policy document for the provided principal, effect, and method ARN.

    Args:
        principal_id (str): The ID of the principal (user) to which the policy applies.
        effect (str): The effect of the policy ('Allow' or 'Deny').
        method_arn (str): The ARN of the method (API endpoint).
        context (dict, optional): Additional context for the policy.

    Returns:
        dict: The generated policy document.
    """
    try:
        logger.info(f"Generating policy for principal_id: {principal_id}, effect: {effect}, method_arn: {method_arn}")
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': method_arn
            }]
        }

        auth_response = {'principalId': principal_id, 'policyDocument': policy_document}
        if context and event_version=="2.0":
            auth_response['context'] = context
        elif context and event_version=="1.0":
            context = flatten_lists(context)
            auth_response['context'] = context

        logger.info(f"Generated policy: {json.dumps(auth_response)}")
        return auth_response
    except Exception as e:
        logger.error(
            f"Error generating policy for principal_id: {principal_id}, effect: {effect}, method_arn: {method_arn}. Error: {str(e)}")
        raise Exception("Unauthorized")
