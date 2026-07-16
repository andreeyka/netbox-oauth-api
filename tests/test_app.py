"""Startup registration of the authentication class into DRF's default chain."""

from django.conf import settings as django_settings

from netbox_keycloak_jwt_auth import AUTHENTICATION_CLASS, register_authentication_class


class TestAuthenticationRegistration:
    def test_registered_at_startup(self):
        # ready() ran during Django setup with REGISTER_AUTHENTICATION enabled.
        classes = django_settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
        assert classes[0] == AUTHENTICATION_CLASS

    def test_drf_defaults_are_preserved(self):
        classes = django_settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
        assert "rest_framework.authentication.SessionAuthentication" in classes

    def test_registration_is_idempotent(self):
        assert register_authentication_class() is False
        classes = django_settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
        assert classes.count(AUTHENTICATION_CLASS) == 1

    def test_registration_can_be_disabled(self, plugin_settings, monkeypatch):
        plugin_settings(REGISTER_AUTHENTICATION=False)
        monkeypatch.setattr(
            django_settings,
            "REST_FRAMEWORK",
            {"DEFAULT_AUTHENTICATION_CLASSES": []},
            raising=False,
        )
        assert register_authentication_class() is False
        assert django_settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] == []

    def test_existing_chain_is_prepended_not_replaced(self, monkeypatch):
        monkeypatch.setattr(
            django_settings,
            "REST_FRAMEWORK",
            {"DEFAULT_AUTHENTICATION_CLASSES": ["myproject.auth.Custom"]},
            raising=False,
        )
        assert register_authentication_class() is True
        assert django_settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] == [
            AUTHENTICATION_CLASS,
            "myproject.auth.Custom",
        ]
