"""End-to-end DRF view tests and startup configuration validation."""

import time

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from netbox_keycloak_jwt_auth.authentication import KeycloakJWTAuthentication
from netbox_keycloak_jwt_auth.settings import get_settings, validate_settings

pytestmark = pytest.mark.django_db

User = get_user_model()


class DummyTokenAuthentication(BaseAuthentication):
    """Stands in for NetBox's native TokenAuthentication in chain tests."""

    def authenticate(self, request):
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not header.startswith("Token "):
            return None
        user = User.objects.filter(username="native-token-user").first()
        return (user, None) if user else None


class WhoAmIView(APIView):
    authentication_classes = [KeycloakJWTAuthentication, DummyTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "username": request.user.username,
                "sub": getattr(request, "keycloak_claims", {}).get("sub"),
            }
        )


def call_view(authorization=None):
    factory = APIRequestFactory()
    extra = {"HTTP_AUTHORIZATION": authorization} if authorization else {}
    request = factory.get("/whoami/", **extra)
    return WhoAmIView.as_view()(request)


class TestAPIViewFlow:
    def test_valid_bearer_token_returns_200(self, token_factory, fake_jwks):
        response = call_view(f"Bearer {token_factory()}")
        assert response.status_code == 200
        assert response.data["username"] == "jdoe"
        assert response.data["sub"] == "11111111-2222-3333-4444-555555555555"

    def test_expired_token_returns_401(self, token_factory, fake_jwks):
        token = token_factory({"exp": int(time.time()) - 3600})
        response = call_view(f"Bearer {token}")
        assert response.status_code == 401

    def test_forged_token_returns_401(self, token_factory, foreign_key, fake_jwks):
        response = call_view(f"Bearer {token_factory(key=foreign_key[1])}")
        assert response.status_code == 401

    def test_no_credentials_returns_401_with_bearer_challenge(self, fake_jwks):
        response = call_view()
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer")

    def test_native_token_auth_still_works(self, fake_jwks):
        # Regression: a non-Bearer scheme falls through to the next backend.
        User.objects.create_user(username="native-token-user")
        response = call_view("Token 0123456789abcdef")
        assert response.status_code == 200
        assert response.data["username"] == "native-token-user"

    def test_error_body_contains_no_details(self, token_factory, fake_jwks):
        token = token_factory({"exp": int(time.time()) - 3600})
        response = call_view(f"Bearer {token}")
        response.render()
        body = response.content.decode()
        assert "expired" not in body.lower().replace("invalid or expired token", "")
        assert token not in body


class TestConfigValidation:
    def test_valid_config_passes(self):
        validate_settings()

    def test_missing_audience_fails_startup(self, plugin_settings):
        plugin_settings(AUDIENCE="")
        with pytest.raises(ImproperlyConfigured, match="AUDIENCE"):
            validate_settings()

    def test_missing_keycloak_url_fails_startup(self, plugin_settings):
        plugin_settings(KEYCLOAK_URL=None)
        with pytest.raises(ImproperlyConfigured, match="KEYCLOAK_URL"):
            validate_settings()

    def test_alg_none_in_config_fails_startup(self, plugin_settings):
        plugin_settings(ALLOWED_ALGORITHMS=["none", "RS256"])
        with pytest.raises(ImproperlyConfigured, match="none"):
            validate_settings()

    def test_symmetric_alg_in_config_fails_startup(self, plugin_settings):
        plugin_settings(ALLOWED_ALGORITHMS=["HS256"])
        with pytest.raises(ImproperlyConfigured):
            validate_settings()

    def test_empty_algorithms_fails_startup(self, plugin_settings):
        plugin_settings(ALLOWED_ALGORITHMS=[])
        with pytest.raises(ImproperlyConfigured):
            validate_settings()

    def test_non_dict_role_mapping_fails_startup(self, plugin_settings):
        plugin_settings(ROLE_GROUP_MAPPING=["netbox-admin"])
        with pytest.raises(ImproperlyConfigured, match="ROLE_GROUP_MAPPING"):
            validate_settings()

    def test_verify_ssl_false_logs_warning(self, plugin_settings, caplog):
        plugin_settings(VERIFY_SSL=False)
        with caplog.at_level("WARNING", logger="netbox_keycloak_jwt_auth"):
            validate_settings()
        assert any("VERIFY_SSL" in record.message for record in caplog.records)

    def test_defaults_are_merged(self, plugin_settings):
        config = get_settings()
        assert config["ALLOWED_ALGORITHMS"] == ["RS256"]
        assert config["USERNAME_CLAIM"] == "preferred_username"
        assert config["USER_CACHE_TTL"] == 60
        assert config["AUDIENCE"] == "netbox"

    def test_issuer_trailing_slash_normalized(self, plugin_settings):
        from netbox_keycloak_jwt_auth.settings import build_issuer, build_jwks_url

        config = plugin_settings(KEYCLOAK_URL="https://keycloak.test/")
        assert build_issuer(config) == "https://keycloak.test/realms/infra"
        assert build_jwks_url(config) == (
            "https://keycloak.test/realms/infra/protocol/openid-connect/certs"
        )
