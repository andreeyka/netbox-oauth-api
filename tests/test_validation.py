"""Token validation: signature, claims, algorithms, JWKS caching and rotation."""

import time

import httpx
import pytest
from rest_framework.exceptions import AuthenticationFailed

from netbox_keycloak_jwt_auth import jwks as jwks_module
from netbox_keycloak_jwt_auth.authentication import GENERIC_ERROR
from netbox_keycloak_jwt_auth.jwks import JWKSError, fetch_jwks
from netbox_keycloak_jwt_auth.settings import get_settings

from .conftest import KID_MAIN, KID_ROTATED, make_jwk

pytestmark = pytest.mark.django_db


class TestBearerHandling:
    def test_valid_token_authenticates(self, auth_request, token_factory, fake_jwks):
        user, auth = auth_request(f"Bearer {token_factory()}")
        assert user.username == "jdoe"
        assert auth is None

    def test_no_header_passes_through(self, auth_request, fake_jwks):
        assert auth_request(None) is None

    def test_token_scheme_passes_through(self, auth_request, fake_jwks):
        assert auth_request("Token 0123456789abcdef") is None

    def test_basic_scheme_passes_through(self, auth_request, fake_jwks):
        assert auth_request("Basic dXNlcjpwYXNz") is None

    def test_bearer_scheme_is_case_insensitive(
        self, auth_request, token_factory, fake_jwks
    ):
        user, _ = auth_request(f"bearer {token_factory()}")
        assert user.username == "jdoe"

    def test_bearer_without_token_fails(self, auth_request, fake_jwks):
        with pytest.raises(AuthenticationFailed):
            auth_request("Bearer")

    def test_bearer_with_extra_parts_fails(self, auth_request, fake_jwks):
        with pytest.raises(AuthenticationFailed):
            auth_request("Bearer abc def")

    def test_garbage_token_fails(self, auth_request, fake_jwks):
        with pytest.raises(AuthenticationFailed):
            auth_request("Bearer not-a-jwt")


class TestClaimValidation:
    def test_expired_token_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory({"exp": int(time.time()) - 3600})
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_expiry_within_clock_skew_accepted(
        self, auth_request, token_factory, fake_jwks
    ):
        token = token_factory({"exp": int(time.time()) - 10})
        user, _ = auth_request(f"Bearer {token}")
        assert user.username == "jdoe"

    def test_not_yet_valid_token_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory({"nbf": int(time.time()) + 3600})
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_wrong_audience_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory({"aud": "other-client"})
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_audience_list_containing_ours_accepted(
        self, auth_request, token_factory, fake_jwks
    ):
        token = token_factory({"aud": ["account", "netbox"]})
        user, _ = auth_request(f"Bearer {token}")
        assert user.username == "jdoe"

    def test_wrong_issuer_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory({"iss": "https://evil.test/realms/infra"})
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_missing_exp_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory({"exp": None})
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_missing_sub_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory({"sub": None})
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_forged_signature_rejected(
        self, auth_request, token_factory, foreign_key, fake_jwks
    ):
        token = token_factory(key=foreign_key[1], kid=KID_MAIN)
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")


class TestAlgorithms:
    def test_alg_none_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory(alg="none")
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_hs256_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory(key="shared-secret", alg="HS256")
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_hs256_rejected_even_if_configured(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        # Defense in depth: symmetric algorithms are stripped at runtime even
        # when a misconfiguration lists them as allowed.
        plugin_settings(ALLOWED_ALGORITHMS=["RS256", "HS256"])
        token = token_factory(key="shared-secret", alg="HS256")
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")


class TestKidAndRotation:
    def test_missing_kid_rejected(self, auth_request, token_factory, fake_jwks):
        token = token_factory(kid=None)
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_unknown_kid_rejected_after_one_refresh(
        self, auth_request, token_factory, fake_jwks
    ):
        token = token_factory(kid="who-dis")
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")
        # initial fetch + one forced refresh
        assert fake_jwks.fetch_count == 2

    def test_key_rotation_without_restart(
        self, auth_request, token_factory, fake_jwks, rotated_key
    ):
        # Prime the JWKS cache with the old key only.
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert fake_jwks.fetch_count == 1

        # Keycloak rotates: new key appears at the endpoint.
        fake_jwks.document["keys"].append(make_jwk(rotated_key[0], KID_ROTATED))
        token = token_factory(key=rotated_key[1], kid=KID_ROTATED)
        user, _ = auth_request(f"Bearer {token}")
        assert user.username == "jdoe"
        assert fake_jwks.fetch_count == 2

    def test_refresh_cooldown_limits_fetches(
        self, auth_request, token_factory, fake_jwks
    ):
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token_factory(kid='unknown-1')}")
        assert fake_jwks.fetch_count == 2

        # A second unknown kid within the cooldown must not hit the endpoint.
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token_factory(kid='unknown-2')}")
        assert fake_jwks.fetch_count == 2

    def test_jwks_cache_reused_between_requests(
        self, auth_request, token_factory, fake_jwks
    ):
        auth_request(f"Bearer {token_factory()}")
        auth_request(f"Bearer {token_factory()}")
        assert fake_jwks.fetch_count == 1

    def test_jwks_error_yields_401(self, auth_request, token_factory, monkeypatch):
        def boom(config):
            raise JWKSError("connection refused")

        monkeypatch.setattr(jwks_module, "fetch_jwks", boom)
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token_factory()}")


class TestErrorHygiene:
    def test_generic_detail_and_warning_log(
        self, auth_request, token_factory, fake_jwks, caplog
    ):
        token = token_factory({"exp": int(time.time()) - 3600})
        with (
            caplog.at_level("WARNING", logger="netbox_keycloak_jwt_auth"),
            pytest.raises(AuthenticationFailed) as excinfo,
        ):
            auth_request(f"Bearer {token}")
        # The client sees a generic message; details go to the log.
        assert str(excinfo.value.detail) == GENERIC_ERROR
        assert any("expired" in record.message.lower() for record in caplog.records)
        # The token itself is never logged.
        assert token not in caplog.text


class TestFetchJWKS:
    def _patch_transport(self, monkeypatch, handler):
        real_client = httpx.Client

        def client_factory(**kwargs):
            return real_client(transport=httpx.MockTransport(handler))

        monkeypatch.setattr(jwks_module.httpx, "Client", client_factory)

    def test_fetch_success(self, monkeypatch):
        def handler(request):
            assert (
                str(request.url)
                == "https://keycloak.test/realms/infra/protocol/openid-connect/certs"
            )
            return httpx.Response(200, json={"keys": []})

        self._patch_transport(monkeypatch, handler)
        assert fetch_jwks(get_settings()) == {"keys": []}

    def test_fetch_http_error(self, monkeypatch):
        self._patch_transport(monkeypatch, lambda request: httpx.Response(503))
        with pytest.raises(JWKSError):
            fetch_jwks(get_settings())

    def test_fetch_invalid_json(self, monkeypatch):
        self._patch_transport(
            monkeypatch, lambda request: httpx.Response(200, content=b"not json")
        )
        with pytest.raises(JWKSError):
            fetch_jwks(get_settings())

    def test_fetch_unexpected_document(self, monkeypatch):
        self._patch_transport(
            monkeypatch, lambda request: httpx.Response(200, json={"nope": True})
        )
        with pytest.raises(JWKSError):
            fetch_jwks(get_settings())
