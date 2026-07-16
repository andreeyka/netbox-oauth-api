"""Mapping of validated token claims onto NetBox users, groups and flags."""

import hashlib
import logging

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import IntegrityError, transaction

from .models import OIDCIdentity

logger = logging.getLogger("netbox_oauth_api")

USER_CACHE_KEY = "jwtauth:sub:{sub}:{roles_hash}"

#: (claim, user field) pairs kept in sync on every request.
PROFILE_FIELDS = (
    ("email", "email"),
    ("given_name", "first_name"),
    ("family_name", "last_name"),
)


class MappingError(Exception):
    """The validated claims cannot be mapped onto a NetBox user."""


def resolve_user(claims, config):
    """Return the NetBox user for *claims*, creating and syncing as configured.

    The result is cached under a key that includes a hash of the roles, so a
    role change at the identity provider takes effect immediately while
    repeat requests with an unchanged token skip all database writes.
    """
    sub = claims.get("sub")
    if not sub:
        raise MappingError("token has no 'sub' claim")

    username = claims.get(config["USERNAME_CLAIM"])
    if not username:
        raise MappingError(f"token has no {config['USERNAME_CLAIM']!r} claim")

    roles = extract_roles(claims, config) if config["GROUP_SYNC_ENABLED"] else []

    cache_key = _user_cache_key(sub, roles)
    user_id = cache.get(cache_key)
    if user_id is not None:
        user = get_user_model().objects.filter(pk=user_id, is_active=True).first()
        if user is not None:
            return user

    user = _get_or_create_user(sub, username, claims, config)

    if config["GROUP_SYNC_ENABLED"]:
        sync_groups(user, roles, config)
        sync_flags(user, roles, config)

    cache.set(cache_key, user.pk, config["USER_CACHE_TTL"])
    return user


def extract_roles(claims, config):
    """Read the role list from ROLES_CLAIM_PATH (dot-separated nested path)."""
    node = claims
    for part in config["ROLES_CLAIM_PATH"].split("."):
        if not isinstance(node, dict):
            return []
        node = node.get(part)
    if not isinstance(node, list):
        return []
    return [str(role) for role in node]


def sync_groups(user, roles, config):
    """Sync membership of managed groups only.

    Groups that are not values of ROLE_GROUP_MAPPING are never touched, so
    locally assigned NetBox groups survive.
    """
    mapping = config["ROLE_GROUP_MAPPING"]
    if not mapping:
        return
    group_model = user._meta.get_field("groups").related_model
    managed_names = set(mapping.values())
    desired_names = {mapping[role] for role in roles if role in mapping}
    current_names = set(
        user.groups.filter(name__in=managed_names).values_list("name", flat=True)
    )

    to_add = desired_names - current_names
    to_remove = current_names - desired_names
    if not to_add and not to_remove:
        return

    groups_to_add = []
    for name in sorted(to_add):
        if config["AUTO_CREATE_GROUPS"]:
            group, created = group_model.objects.get_or_create(name=name)
            if created:
                logger.info("created group %r", name)
        else:
            group = group_model.objects.filter(name=name).first()
            if group is None:
                logger.warning(
                    "group %r does not exist and AUTO_CREATE_GROUPS is disabled", name
                )
                continue
        groups_to_add.append(group)

    if groups_to_add:
        user.groups.add(*groups_to_add)
    if to_remove:
        user.groups.remove(*group_model.objects.filter(name__in=to_remove))
    logger.info(
        "synced groups for user %s: added=%s removed=%s",
        user.username,
        sorted(group.name for group in groups_to_add),
        sorted(to_remove),
    )


def sync_flags(user, roles, config):
    """Set is_superuser / is_staff from roles.

    An empty SUPERUSER_ROLES / STAFF_ROLES list means the corresponding flag
    is not managed by the plugin at all.
    """
    role_set = set(roles)
    changed = []
    for setting_name, field in (
        ("SUPERUSER_ROLES", "is_superuser"),
        ("STAFF_ROLES", "is_staff"),
    ):
        managed_roles = config[setting_name]
        if not managed_roles:
            continue
        if not hasattr(user, field):
            # NetBox 4.5 dropped the Django admin and with it User.is_staff;
            # skip the flag instead of failing every authenticated request.
            logger.warning(
                "%s is configured but the user model has no %r field — ignored",
                setting_name,
                field,
            )
            continue
        desired = bool(role_set.intersection(managed_roles))
        if getattr(user, field) != desired:
            setattr(user, field, desired)
            changed.append(field)
    if changed:
        user.save(update_fields=changed)
        logger.info(
            "updated flags for user %s: %s",
            user.username,
            ", ".join(f"{field}={getattr(user, field)}" for field in changed),
        )


def _user_cache_key(sub, roles):
    roles_hash = hashlib.sha256("\n".join(sorted(roles)).encode()).hexdigest()[:16]
    return USER_CACHE_KEY.format(sub=sub, roles_hash=roles_hash)


def _get_or_create_user(sub, username, claims, config):
    user_model = get_user_model()

    identity = OIDCIdentity.objects.select_related("user").filter(sub=sub).first()
    if identity is not None:
        user = identity.user
        identity.save(update_fields=["last_seen"])
        _maybe_rename(user, username)
    else:
        user = user_model.objects.filter(username=username).first()
        if user is None:
            if not config["AUTO_CREATE_USER"]:
                raise MappingError(
                    f"user {username!r} does not exist and AUTO_CREATE_USER is disabled"
                )
            user = _create_user(username, claims)
        elif OIDCIdentity.objects.filter(user=user).exists():
            # The username matches a NetBox user already linked to a different
            # identity-provider account — refuse instead of hijacking it.
            raise MappingError(
                f"user {username!r} is already linked to a different OIDC sub"
            )
        try:
            OIDCIdentity.objects.get_or_create(sub=sub, defaults={"user": user})
        except IntegrityError as exc:
            raise MappingError(
                f"cannot link user {username!r} to OIDC identity: {exc}"
            ) from exc

    if not user.is_active:
        raise MappingError(f"user {user.username!r} is disabled")

    _sync_profile(user, claims)
    return user


def _create_user(username, claims):
    user_model = get_user_model()
    field_values = {
        field: _clamp(user_model, field, str(claims.get(claim) or ""))
        for claim, field in PROFILE_FIELDS
    }
    try:
        with transaction.atomic():
            user = user_model(username=username, is_active=True, **field_values)
            user.set_unusable_password()
            user.save()
    except IntegrityError as exc:
        # Another worker created the same user concurrently.
        user = user_model.objects.filter(username=username).first()
        if user is None:
            raise MappingError(f"failed to create user {username!r}") from exc
        return user
    logger.info("created user %s from OIDC token", username)
    return user


def _maybe_rename(user, username):
    """Follow a username change at the provider (the user was matched by sub)."""
    if user.username == username:
        return
    user_model = get_user_model()
    if user_model.objects.filter(username=username).exclude(pk=user.pk).exists():
        logger.warning(
            "cannot rename user %s to %s: username is already taken",
            user.username,
            username,
        )
        return
    logger.info(
        "renaming user %s to %s (changed at the identity provider)",
        user.username,
        username,
    )
    user.username = username
    user.save(update_fields=["username"])


def _sync_profile(user, claims):
    """Update email / first_name / last_name, writing only on an actual diff."""
    changed = []
    for claim, field in PROFILE_FIELDS:
        value = claims.get(claim)
        if value is None:
            continue
        value = _clamp(user.__class__, field, str(value))
        if getattr(user, field) != value:
            setattr(user, field, value)
            changed.append(field)
    if changed:
        user.save(update_fields=changed)


def _clamp(model, field, value):
    max_length = model._meta.get_field(field).max_length
    return value[:max_length] if max_length else value
