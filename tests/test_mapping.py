"""User creation, identity linking, profile/group/flag sync and caching."""

from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.exceptions import AuthenticationFailed

from netbox_oauth_api import mapping
from netbox_oauth_api.mapping import MappingError, extract_roles, resolve_user
from netbox_oauth_api.models import OIDCIdentity
from netbox_oauth_api.settings import get_settings

pytestmark = pytest.mark.django_db

User = get_user_model()
SUB = "11111111-2222-3333-4444-555555555555"


class TestUserCreation:
    def test_auto_create_user(self, auth_request, token_factory, fake_jwks):
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert user.username == "jdoe"
        assert user.email == "jdoe@example.com"
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.is_active
        assert not user.has_usable_password()
        assert user.oidc_identity.sub == SUB

    def test_auto_create_disabled_rejects_unknown_user(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(AUTO_CREATE_USER=False)
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token_factory()}")
        assert not User.objects.filter(username="jdoe").exists()

    def test_auto_create_disabled_allows_existing_user(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(AUTO_CREATE_USER=False)
        existing = User.objects.create_user(username="jdoe")
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert user.pk == existing.pk
        assert existing.oidc_identity.sub == SUB

    def test_missing_username_claim_rejected(
        self, auth_request, token_factory, fake_jwks
    ):
        token = token_factory({"preferred_username": None})
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token}")

    def test_custom_username_claim(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(USERNAME_CLAIM="email")
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert user.username == "jdoe@example.com"

    def test_inactive_user_rejected(self, auth_request, token_factory, fake_jwks):
        user = User.objects.create_user(username="jdoe", is_active=False)
        OIDCIdentity.objects.create(user=user, sub=SUB)
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token_factory()}")

    def test_username_linked_to_other_sub_rejected(
        self, auth_request, token_factory, fake_jwks
    ):
        user = User.objects.create_user(username="jdoe")
        OIDCIdentity.objects.create(user=user, sub="another-sub")
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token_factory()}")


class TestIdentityAndRename:
    def test_rename_at_idp_reuses_user_by_sub(
        self, auth_request, token_factory, fake_jwks
    ):
        from django.core.cache import cache

        user, _ = auth_request(f"Bearer {token_factory()}")
        cache.clear()  # simulate USER_CACHE_TTL expiry
        renamed, _ = auth_request(
            f"Bearer {token_factory({'preferred_username': 'john.doe'})}"
        )
        assert renamed.pk == user.pk
        assert renamed.username == "john.doe"
        assert User.objects.count() == 1

    def test_rename_conflict_keeps_old_username(
        self, auth_request, token_factory, fake_jwks
    ):
        from django.core.cache import cache

        User.objects.create_user(username="john.doe")
        user, _ = auth_request(f"Bearer {token_factory()}")
        cache.clear()  # simulate USER_CACHE_TTL expiry
        renamed, _ = auth_request(
            f"Bearer {token_factory({'preferred_username': 'john.doe'})}"
        )
        assert renamed.pk == user.pk
        assert renamed.username == "jdoe"

    def test_last_seen_updated(self, auth_request, token_factory, fake_jwks):
        auth_request(f"Bearer {token_factory()}")
        first = OIDCIdentity.objects.get(sub=SUB).last_seen
        # The user cache is keyed by sub+roles; a role change forces the full path.
        auth_request(f"Bearer {token_factory({'roles': ['netbox-write']})}")
        assert OIDCIdentity.objects.get(sub=SUB).last_seen >= first


class TestProfileSync:
    def test_profile_updated_on_change(self, auth_request, token_factory, fake_jwks):
        auth_request(f"Bearer {token_factory()}")
        token = token_factory(
            {
                "email": "new@example.com",
                "given_name": "Johnny",
                # bust the user cache so the full mapping path runs
                "roles": ["netbox-write"],
            }
        )
        user, _ = auth_request(f"Bearer {token}")
        assert user.email == "new@example.com"
        assert user.first_name == "Johnny"
        assert user.last_name == "Doe"

    def test_no_write_without_diff(self, fake_jwks):
        user = User.objects.create_user(
            username="jdoe",
            email="jdoe@example.com",
            first_name="John",
            last_name="Doe",
        )
        claims = {
            "email": "jdoe@example.com",
            "given_name": "John",
            "family_name": "Doe",
        }
        with mock.patch.object(user, "save") as save:
            mapping._sync_profile(user, claims)
        save.assert_not_called()

    def test_absent_claims_do_not_clear_fields(self, fake_jwks):
        user = User.objects.create_user(username="jdoe", email="keep@example.com")
        with mock.patch.object(user, "save") as save:
            mapping._sync_profile(user, {})
        save.assert_not_called()
        assert user.email == "keep@example.com"


class TestRolesExtraction:
    def test_default_path(self):
        claims = {"roles": ["a", "b"]}
        assert extract_roles(claims, get_settings()) == ["a", "b"]

    def test_nested_path(self, plugin_settings):
        # e.g. Keycloak realm roles live at realm_access.roles
        config = plugin_settings(ROLES_CLAIM_PATH="realm_access.roles")
        claims = {"realm_access": {"roles": ["x"]}}
        assert extract_roles(claims, config) == ["x"]

    def test_missing_path_returns_empty(self):
        assert extract_roles({}, get_settings()) == []

    def test_non_list_returns_empty(self):
        claims = {"roles": "not-a-list"}
        assert extract_roles(claims, get_settings()) == []

    def test_non_dict_intermediate_returns_empty(self, plugin_settings):
        config = plugin_settings(ROLES_CLAIM_PATH="realm_access.roles")
        claims = {"realm_access": "oops"}
        assert extract_roles(claims, config) == []


class TestGroupSync:
    def test_groups_created_and_assigned(self, auth_request, token_factory, fake_jwks):
        token = token_factory({"roles": ["netbox-read", "netbox-admin", "unmapped"]})
        user, _ = auth_request(f"Bearer {token}")
        names = set(user.groups.values_list("name", flat=True))
        assert names == {"NetBox Readers", "NetBox Administrators"}

    def test_removed_role_unassigns_managed_group_only(
        self, auth_request, token_factory, fake_jwks
    ):
        local = Group.objects.create(name="Local Team")
        user, _ = auth_request(f"Bearer {token_factory()}")
        user.groups.add(local)

        token = token_factory({"roles": []})
        user, _ = auth_request(f"Bearer {token}")
        assert set(user.groups.values_list("name", flat=True)) == {"Local Team"}

    def test_group_sync_disabled(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(GROUP_SYNC_ENABLED=False)
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert user.groups.count() == 0

    def test_auto_create_groups_disabled(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(AUTO_CREATE_GROUPS=False)
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert user.groups.count() == 0
        assert not Group.objects.filter(name="NetBox Readers").exists()

    def test_auto_create_groups_disabled_uses_existing(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(AUTO_CREATE_GROUPS=False)
        Group.objects.create(name="NetBox Readers")
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert set(user.groups.values_list("name", flat=True)) == {"NetBox Readers"}

    def test_empty_mapping_is_noop(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(ROLE_GROUP_MAPPING={})
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert user.groups.count() == 0


class TestFlagSync:
    def test_superuser_and_staff_roles(
        self, auth_request, token_factory, fake_jwks, plugin_settings
    ):
        plugin_settings(SUPERUSER_ROLES=["netbox-admin"], STAFF_ROLES=["netbox-admin"])
        token = token_factory({"roles": ["netbox-admin"]})
        user, _ = auth_request(f"Bearer {token}")
        assert user.is_superuser
        assert user.is_staff

        # Role removed at the provider → flags are dropped on the next token.
        token = token_factory({"roles": ["netbox-read"]})
        user, _ = auth_request(f"Bearer {token}")
        assert not user.is_superuser
        assert not user.is_staff

    def test_empty_lists_leave_flags_alone(
        self, auth_request, token_factory, fake_jwks
    ):
        user = User.objects.create_user(
            username="jdoe", is_staff=True, is_superuser=True
        )
        OIDCIdentity.objects.create(user=user, sub=SUB)
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert user.is_staff
        assert user.is_superuser

    def test_missing_flag_field_is_skipped_with_warning(self, caplog):
        # NetBox 4.5 removed User.is_staff together with the Django admin;
        # a configured STAFF_ROLES must be ignored, not crash every request.
        class AdminlessUser:
            username = "jdoe"
            is_superuser = False

            def save(self, update_fields=None):
                self.saved_fields = update_fields

        user = AdminlessUser()
        config = {"SUPERUSER_ROLES": ["netbox-admin"], "STAFF_ROLES": ["netbox-admin"]}
        with caplog.at_level("WARNING", logger="netbox_oauth_api"):
            mapping.sync_flags(user, ["netbox-admin"], config)
        assert user.is_superuser
        assert user.saved_fields == ["is_superuser"]
        assert any("STAFF_ROLES" in record.message for record in caplog.records)


class TestUserCache:
    def test_cache_hit_skips_mapping(
        self, auth_request, token_factory, fake_jwks, monkeypatch
    ):
        user, _ = auth_request(f"Bearer {token_factory()}")

        def boom(*args, **kwargs):
            raise AssertionError("full mapping path must not run on cache hit")

        monkeypatch.setattr(mapping, "_get_or_create_user", boom)
        cached, _ = auth_request(f"Bearer {token_factory()}")
        assert cached.pk == user.pk

    def test_role_change_busts_cache_immediately(
        self, auth_request, token_factory, fake_jwks
    ):
        user, _ = auth_request(f"Bearer {token_factory()}")
        assert set(user.groups.values_list("name", flat=True)) == {"NetBox Readers"}

        token = token_factory({"roles": ["netbox-admin"]})
        user, _ = auth_request(f"Bearer {token}")
        assert set(user.groups.values_list("name", flat=True)) == {
            "NetBox Administrators"
        }

    def test_stale_cached_user_recovers(self, auth_request, token_factory, fake_jwks):
        user, _ = auth_request(f"Bearer {token_factory()}")
        user.delete()
        recreated, _ = auth_request(f"Bearer {token_factory()}")
        assert recreated.username == "jdoe"
        assert recreated.pk != user.pk

    def test_deactivated_user_not_served_from_cache(
        self, auth_request, token_factory, fake_jwks
    ):
        user, _ = auth_request(f"Bearer {token_factory()}")
        User.objects.filter(pk=user.pk).update(is_active=False)
        with pytest.raises(AuthenticationFailed):
            auth_request(f"Bearer {token_factory()}")


class TestResolveUserErrors:
    def test_missing_sub_raises(self, fake_jwks):
        with pytest.raises(MappingError):
            resolve_user({"preferred_username": "jdoe"}, get_settings())
