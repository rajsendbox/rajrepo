#!/bin/bash

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <ENV_NAME> <REGION>"
    exit 1
fi

ENV_NAME=$1
REGION=$2
KEYCLOAK_BASE_URL="https://${ENV_NAME}.auth.identra.ai"
LAMBDA_AUTH_DIR="../../infra-tf/$ENV_NAME/$REGION/lambda-auth-3"
EMPOWER_BASE_URL="https://${ENV_NAME}.app.identra.ai"
pip install -r ../requirements.txt

export KEYCLOAK_BASE_URL=$KEYCLOAK_BASE_URL
export EMPOWER_BASE_URL=$EMPOWER_BASE_URL

# python3 update_resources_in_config.py
# python3 setup_kc.py --env $ENV_NAME > setup_kc_logs.txt
python3 setup_kc.py --env $ENV_NAME 
python3 wrapper.py --env $ENV_NAME > output.json

# echo "--------------------- 'setup_kc_logs.txt' file START ---------------------"
# cat setup_kc_logs.txt
# echo "--------------------- 'setup_kc_logs.txt' file END ---------------------"

# echo "--------------------- 'output.json' file START ---------------------"
# cat output.json
# echo "--------------------- 'output.json' file END ---------------------"

echo " - Running authz - "

bash loop.sh "$ENV_NAME"
# bash loop.sh "$ENV_NAME" > setup_authz_logs.txt

# echo "--------------------- 'setup_authz_logs.txt' file START ---------------------"
# cat setup_authz_logs.txt
# echo "--------------------- 'setup_authz_logs.txt' file END ---------------------"

mv config ../../lambda_authorizer/app

cd ../../lambda_authorizer/app || exit
zip -r app.zip *

mv app.zip $LAMBDA_AUTH_DIR

cd ../../infra-tf/$ENV_NAME/$REGION || exit

terragrunt run-all apply -auto-approve --terragrunt-non-interactive=true

echo " - Deployment completed successfully. - "