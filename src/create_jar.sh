#!/bin/bash

# Define paths
PROJECT_ROOT=$(pwd)
TARGET_FOLDER="keycloak_artefacts"
OUTPUT_ZIP="keycloak_artefacts.jar"
ARTEFACTS_RAW="keycloak_artefacts_raw"

# Navigate to the target folder
cd "$PROJECT_ROOT/$ARTEFACTS_RAW" || {
  echo "Error: ARTEFACTS_RAW folder does not exist."
  exit 1
}

# Create the ZIP archive from the contents of the target folder
zip -r "$PROJECT_ROOT/$TARGET_FOLDER/$OUTPUT_ZIP" ./*

# Navigate back to the project root
cd "$PROJECT_ROOT"

echo "ZIP file created: $OUTPUT_ZIP"