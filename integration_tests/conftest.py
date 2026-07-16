"""Fixtures for the end-to-end suite against the docker-compose stack.

The suite talks plain HTTP to the published ports of the stack defined in
docker/docker-compose.yml — it needs neither Django nor the plugin itself.
All endpoints and credentials can be overridden through E2E_* environment
variables (defaults match docker-compose.yml).
"""

import os
import time

import httpx
import pytest

NETBOX_URL = os.environ.get("E2E_NETBOX_URL", "http://localhost:8000").rstrip("/")
KEYCLOAK_URL = os.environ.get("E2E_KEYCLOAK_URL", "http://localhost:8081").rstrip("/")
#: Issuer as NetBox sees it from inside the compose network (KC_HOSTNAME).
INTERNAL_ISSUER = os.environ.get(
    "E2E_INTERNAL_ISSUER", "http://keycloak:8080/realms/infra"
)
REALM = os.environ.get("E2E_REALM", "infra")
CLIENT_ID = os.environ.get("E2E_CLIENT_ID", "netbox")
SUPERUSER_TOKEN = os.environ.get(
    "E2E_SUPERUSER_TOKEN", "0123456789abcdef0123456789abcdef01234567"
)
WAIT_TIMEOUT = int(os.environ.get("E2E_WAIT_TIMEOUT", "600"))

TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"

#: Test users provisioned by docker/keycloak/realm-infra.json.
PASSWORDS = {
    "alice": "alice-password",  # realm role netbox-admin
    "bob": "bob-password",  # realm role netbox-read
    "carol": "carol-password",  # no roles
}


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def native():
    """NetBox's own token scheme, using the compose-provisioned superuser."""
    return {"Authorization": f"Token {SUPERUSER_TOKEN}"}


def _wait_until(check, description):
    deadline = time.monotonic() + WAIT_TIMEOUT
    last_error = None
    while time.monotonic() < deadline:
        try:
            if check():
                return
            last_error = None
        except Exception as exc:  # noqa: BLE001 — retried until the deadline
            last_error = exc
        time.sleep(3)
    pytest.fail(
        f"{description} did not become ready within {WAIT_TIMEOUT}s: {last_error}"
    )


@pytest.fixture(scope="session", autouse=True)
def stack_ready():
    """Block until both Keycloak and NetBox answer over HTTP."""
    with httpx.Client(timeout=10) as client:
        _wait_until(
            lambda: (
                client.get(
                    f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration"
                ).status_code
                == 200
            ),
            f"Keycloak at {KEYCLOAK_URL}",
        )
        _wait_until(
            lambda: client.get(f"{NETBOX_URL}/login/").status_code == 200,
            f"NetBox at {NETBOX_URL}",
        )


@pytest.fixture(scope="session")
def netbox():
    with httpx.Client(base_url=f"{NETBOX_URL}/api", timeout=30) as client:
        yield client


@pytest.fixture(scope="session")
def get_token():
    """Obtain a real access token from Keycloak via the password grant."""

    def _get(username):
        response = httpx.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "username": username,
                "password": PASSWORDS[username],
            },
            timeout=30,
        )
        response.raise_for_status()
        return response.json()["access_token"]

    return _get


@pytest.fixture(scope="session")
def alice_token(get_token, stack_ready):
    return get_token("alice")


@pytest.fixture(scope="session")
def bob_token(get_token, stack_ready):
    return get_token("bob")


@pytest.fixture(scope="session")
def carol_token(get_token, stack_ready):
    return get_token("carol")
