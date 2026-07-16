"""End-to-end tests: real Keycloak tokens against a real NetBox instance.

Requires the stack from docker/docker-compose.yml to be running; see the
Makefile targets `integration` / `integration-all`.
"""

import time
import uuid

import httpx
import jwt
from conftest import (
    INTERNAL_ISSUER,
    KEYCLOAK_URL,
    REALM,
    TOKEN_ENDPOINT,
    bearer,
    native,
)


class TestKeycloakSanity:
    """Guards against stack misconfiguration with readable failures."""

    def test_discovery_issuer_matches_internal_hostname(self):
        # KC_HOSTNAME pins the issuer to the in-network URL; if this breaks,
        # every Bearer request would fail with an issuer mismatch.
        document = httpx.get(
            f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration",
            timeout=30,
        ).json()
        assert document["issuer"] == INTERNAL_ISSUER

    def test_access_token_carries_expected_claims(self, alice_token):
        claims = jwt.decode(alice_token, options={"verify_signature": False})
        assert claims["iss"] == INTERNAL_ISSUER
        assert "netbox" in (
            claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        )
        assert claims["preferred_username"] == "alice"
        assert "netbox-admin" in claims["realm_access"]["roles"]

    def test_wrong_password_is_rejected_by_keycloak(self):
        response = httpx.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "password",
                "client_id": "netbox",
                "username": "alice",
                "password": "wrong-password",
            },
            timeout=30,
        )
        assert response.status_code == 401


class TestBearerAuthentication:
    def test_admin_bearer_token_can_read_api(self, netbox, alice_token):
        response = netbox.get("/dcim/sites/", headers=bearer(alice_token))
        assert response.status_code == 200
        assert "results" in response.json()

    def test_superuser_role_grants_write_access(self, netbox, alice_token):
        # SUPERUSER_ROLES: ["netbox-admin"] — alice may create objects.
        slug = f"e2e-{uuid.uuid4().hex[:8]}"
        response = netbox.post(
            "/dcim/sites/",
            headers=bearer(alice_token),
            json={"name": f"E2E {slug}", "slug": slug},
        )
        assert response.status_code == 201, response.text
        site_id = response.json()["id"]
        deleted = netbox.delete(f"/dcim/sites/{site_id}/", headers=bearer(alice_token))
        assert deleted.status_code == 204

    def test_user_is_autocreated_with_profile_from_token(self, netbox, alice_token):
        netbox.get("/dcim/sites/", headers=bearer(alice_token)).raise_for_status()
        response = netbox.get(
            "/users/users/", headers=native(), params={"username": "alice"}
        )
        assert response.status_code == 200
        results = response.json()["results"]
        assert len(results) == 1
        alice = results[0]
        assert alice["email"] == "alice@example.com"
        assert alice["first_name"] == "Alice"
        assert alice["last_name"] == "Admin"

    def test_mapped_groups_are_autocreated(self, netbox, alice_token, bob_token):
        netbox.get("/dcim/sites/", headers=bearer(alice_token))
        netbox.get("/dcim/sites/", headers=bearer(bob_token))
        for name in ("NetBox Administrators", "NetBox Readers"):
            response = netbox.get(
                "/users/groups/", headers=native(), params={"name": name}
            )
            assert response.status_code == 200
            assert response.json()["count"] == 1, f"group {name!r} was not created"

    def test_reader_without_object_permission_gets_403(self, netbox, bob_token):
        response = netbox.get("/dcim/sites/", headers=bearer(bob_token))
        assert response.status_code == 403

    def test_object_permission_on_mapped_group_applies(self, netbox, bob_token):
        # bob's first request created him and put him into "NetBox Readers";
        # granting that group a view permission must open read access — this
        # also proves the group membership really landed in the database.
        netbox.get("/dcim/sites/", headers=bearer(bob_token))
        groups = netbox.get(
            "/users/groups/", headers=native(), params={"name": "NetBox Readers"}
        ).json()["results"]
        assert len(groups) == 1

        permission = netbox.post(
            "/users/permissions/",
            headers=native(),
            json={
                "name": f"e2e-readers-view-sites-{uuid.uuid4().hex[:8]}",
                "enabled": True,
                "actions": ["view"],
                "object_types": ["dcim.site"],
                "groups": [groups[0]["id"]],
            },
        )
        assert permission.status_code == 201, permission.text
        permission_id = permission.json()["id"]
        try:
            # The plugin's user cache is 1s in the compose stack.
            time.sleep(2)
            read = netbox.get("/dcim/sites/", headers=bearer(bob_token))
            assert read.status_code == 200
            write = netbox.post(
                "/dcim/sites/",
                headers=bearer(bob_token),
                json={"name": "E2E denied", "slug": "e2e-denied"},
            )
            assert write.status_code == 403
        finally:
            netbox.delete(f"/users/permissions/{permission_id}/", headers=native())

    def test_user_without_roles_is_authenticated_but_forbidden(
        self, netbox, carol_token
    ):
        response = netbox.get("/dcim/sites/", headers=bearer(carol_token))
        assert response.status_code == 403
        found = netbox.get(
            "/users/users/", headers=native(), params={"username": "carol"}
        ).json()
        assert found["count"] == 1


class TestNegative:
    def test_garbage_bearer_token_is_rejected(self, netbox):
        response = netbox.get("/dcim/sites/", headers=bearer("not-a-jwt"))
        assert response.status_code == 401

    def test_forged_token_with_unknown_key_is_rejected(self, netbox):
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        forged = jwt.encode(
            {
                "iss": INTERNAL_ISSUER,
                "aud": "netbox",
                "sub": str(uuid.uuid4()),
                "iat": now,
                "exp": now + 300,
                "preferred_username": "mallory",
                "realm_access": {"roles": ["netbox-admin"]},
            },
            key,
            algorithm="RS256",
            headers={"kid": "e2e-forged"},
        )
        response = netbox.get("/dcim/sites/", headers=bearer(forged))
        assert response.status_code == 401

    def test_request_without_credentials_is_rejected(self, netbox):
        response = netbox.get("/dcim/sites/")
        assert response.status_code in (401, 403)

    def test_native_netbox_token_still_works(self, netbox):
        # Regression: the plugin must pass non-Bearer schemes down the chain.
        response = netbox.get("/dcim/sites/", headers=native())
        assert response.status_code == 200
