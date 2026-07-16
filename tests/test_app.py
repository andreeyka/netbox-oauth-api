"""Startup registration of the authentication class into DRF's default chain."""

from django.conf import settings as django_settings

from netbox_oauth_api import AUTHENTICATION_CLASS, register_authentication_class


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

    def test_already_imported_apiview_is_updated(self, monkeypatch):
        # NetBox imports rest_framework.views before plugin ready() runs, so
        # APIView holds a stale copy of the default chain that must be fixed.
        from rest_framework.views import APIView

        from netbox_oauth_api.authentication import OIDCJWTAuthentication

        monkeypatch.setattr(
            django_settings,
            "REST_FRAMEWORK",
            {
                "DEFAULT_AUTHENTICATION_CLASSES": [
                    "rest_framework.authentication.SessionAuthentication"
                ]
            },
            raising=False,
        )
        monkeypatch.setattr(APIView, "authentication_classes", [])
        assert register_authentication_class() is True
        assert OIDCJWTAuthentication in APIView.authentication_classes

    def test_existing_chain_is_prepended_not_replaced(self, monkeypatch):
        existing = "rest_framework.authentication.BasicAuthentication"
        monkeypatch.setattr(
            django_settings,
            "REST_FRAMEWORK",
            {"DEFAULT_AUTHENTICATION_CLASSES": [existing]},
            raising=False,
        )
        assert register_authentication_class() is True
        assert django_settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] == [
            AUTHENTICATION_CLASS,
            existing,
        ]
