#!/bin/bash

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ENV_NAME>"
    exit 1
fi

ENV_NAME=$1

OUTPUT_FILE="output.json"
# OUTPUT_FILE="output_local.json"
PYTHON_SCRIPT="setup_authz.py"

if [[ ! -f "$OUTPUT_FILE" ]]; then
    echo "Error: $OUTPUT_FILE not found."
    exit 1
fi

REALMS=$(jq -c '.[]' "$OUTPUT_FILE")

if [[ -z "$REALMS" ]]; then
    echo "Error: No realms found in $OUTPUT_FILE."
    exit 1
fi

while IFS= read -r REALM; do
    REALM_NAME=$(echo "$REALM" | jq -r '.REALM_NAME')
    REALM_ADMIN_USER=$(echo "$REALM" | jq -r '.REALM_ADMIN_USER')
    REALM_ADMIN_PASSWORD=$(echo "$REALM" | jq -r '.REALM_ADMIN_PASSWORD')
    KEYCLOAK_BASE_URL=$(echo "$REALM" | jq -r '.KEYCLOAK_BASE_URL')

    echo "Processing realm: $REALM_NAME"
    
    python3 "$PYTHON_SCRIPT" "$REALM_NAME" "$REALM_ADMIN_USER" "$REALM_ADMIN_PASSWORD" "$KEYCLOAK_BASE_URL" "$ENV_NAME" 

    if [[ $? -ne 0 ]]; then
        echo "Error: Python script failed for realm $REALM_NAME."
        exit 1
    fi

done <<< "$REALMS"

echo "All realms processed successfully."