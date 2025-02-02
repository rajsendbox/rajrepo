import boto3
import os
from botocore.exceptions import ClientError
import json
import argparse

def get_secret(secret_name, region_name="us-west-2", env="default"):
    """
    Retrieve a secret value from AWS Secrets Manager.

    :param secret_name: Name of the secret in Secrets Manager
    :param region_name: AWS region where the Secrets Manager is located
    :param env: Environment variable to construct the URL
    :return: Secret value as a dictionary
    """
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        # Fetch the secret value
        response = client.get_secret_value(SecretId=secret_name)
        if 'SecretString' in response:
            secret = response['SecretString']
            secret_dict = json.loads(secret)
            # Reformat the output
            formatted_secrets = []
            for realm, values in secret_dict.items():
                # TODO: remove and condition 'and realm == "merumesh-authz"' 'and realm == "merumesh"'
                if realm != "master" and (realm == "merumesh" or realm == "merumesh-authz" or realm == "identra"):  # Ignore the master realm
                    formatted_secrets.append({
                        "REALM_NAME": realm,
                        "REALM_ADMIN_USER": values.get("KEYCLOAK_ADMIN"),
                        "REALM_ADMIN_PASSWORD": values.get("KEYCLOAK_ADMIN_PASSWORD"),
                        "KEYCLOAK_BASE_URL": f"https://{env}.auth.identra.ai"
                    })
            return formatted_secrets
        else:
            # If the secret is binary, decode it as needed
            secret = response['SecretBinary']
            return secret
    except ClientError as e:
        print(f"Failed to retrieve secret {secret_name}: {e}")
        return None

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Fetch secrets from AWS Secrets Manager")
    parser.add_argument('--env', required=True, help="Environment name (e.g., dev, prod)")
    parser.add_argument('--region', default="us-west-2", help="AWS region name")

    args = parser.parse_args()

    secret_name = "keyclock/admin/creds"  # Hardcoded secret name
    region = args.region
    env = args.env

    secret_value = get_secret(secret_name, region, env)
    if secret_value:
        # Print the secret in JSON format
        print(json.dumps(secret_value, indent=4))
    else:
        print("Failed to retrieve secret.")
