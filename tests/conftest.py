"""Shared fixtures: RSA keys, a fake JWKS endpoint and a token factory."""

import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from netbox_keycloak_jwt_auth import jwks as jwks_module

ISSUER = "https://keycloak.test/realms/infra"
KID_MAIN = "main-key"
KID_ROTATED = "rotated-key"


def _generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, private_pem


def make_jwk(private_key, kid):
    data = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    data.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return data


@pytest.fixture(scope="session")
def main_key():
    return _generate_keypair()


@pytest.fixture(scope="session")
def rotated_key():
    return _generate_keypair()


@pytest.fixture(scope="session")
def foreign_key():
    """A key that is never published in the fake JWKS."""
    return _generate_keypair()


@pytest.fixture(autouse=True)
def _clear_django_cache():
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


class FakeJWKS:
    """Mutable stand-in for the Keycloak JWKS endpoint."""

    def __init__(self, keys):
        self.document = {"keys": keys}
        self.fetch_count = 0

    def __call__(self, config):
        self.fetch_count += 1
        return self.document


@pytest.fixture
def fake_jwks(monkeypatch, main_key):
    fake = FakeJWKS([make_jwk(main_key[0], KID_MAIN)])
    monkeypatch.setattr(jwks_module, "fetch_jwks", fake)
    return fake


@pytest.fixture
def token_factory(main_key):
    """Build a signed JWT; override claims via dict (None removes a claim)."""

    def make_token(claims=None, *, key=None, kid=KID_MAIN, alg="RS256", headers=None):
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": "netbox",
            "sub": "11111111-2222-3333-4444-555555555555",
            "jti": str(uuid.uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "preferred_username": "jdoe",
            "email": "jdoe@example.com",
            "given_name": "John",
            "family_name": "Doe",
            "realm_access": {"roles": ["netbox-read"]},
        }
        payload.update(claims or {})
        payload = {k: v for k, v in payload.items() if v is not None}
        jwt_headers = {"kid": kid} if kid else {}
        jwt_headers.update(headers or {})
        if alg == "none":
            return jwt.encode(payload, None, algorithm="none", headers=jwt_headers or None)
        signing_key = key if key is not None else main_key[1]
        return jwt.encode(payload, signing_key, algorithm=alg, headers=jwt_headers or None)

    return make_token


@pytest.fixture
def plugin_settings(settings):
    """Override individual plugin settings for a single test."""

    def _override(**kwargs):
        merged = {**settings.PLUGINS_CONFIG["netbox_keycloak_jwt_auth"], **kwargs}
        settings.PLUGINS_CONFIG = {"netbox_keycloak_jwt_auth": merged}
        return merged

    return _override


@pytest.fixture
def auth_request():
    """Run KeycloakJWTAuthentication against a request with the given header."""
    from rest_framework.test import APIRequestFactory

    from netbox_keycloak_jwt_auth.authentication import KeycloakJWTAuthentication

    def _authenticate(authorization=None):
        factory = APIRequestFactory()
        extra = {"HTTP_AUTHORIZATION": authorization} if authorization else {}
        request = factory.get("/api/", **extra)
        return KeycloakJWTAuthentication().authenticate(request)

    return _authenticate
