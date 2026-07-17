# NetBox with netbox-oauth-api installed from the local checkout.
# Build context is the repository root (see docker-compose.yml).

ARG NETBOX_IMAGE=docker.io/netboxcommunity/netbox
ARG NETBOX_IMAGE_TAG=v4.6

FROM ${NETBOX_IMAGE}:${NETBOX_IMAGE_TAG}

COPY . /opt/netbox-oauth-api/

# Recent netbox-docker generations manage /opt/netbox/venv with uv; the
# older v4.0-era images still carry pip inside the venv.
RUN if command -v uv >/dev/null 2>&1; then \
        uv pip install /opt/netbox-oauth-api/; \
    else \
        /opt/netbox/venv/bin/pip install /opt/netbox-oauth-api/; \
    fi
