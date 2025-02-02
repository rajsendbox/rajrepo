
# Use the official Python image as a base image
FROM quay.io/keycloak/keycloak:26.0.6

# Copy the requirements file into the container at /code
COPY keycloak_artefacts/ /opt/keycloak/providers/

ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_FEATURES=scripts

COPY themes/ /opt/keycloak/themes/

RUN /opt/keycloak/bin/kc.sh build --features=scripts --verbose
