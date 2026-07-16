from django.conf import settings
from django.db import models


class KeycloakIdentity(models.Model):
    """Stable link between a NetBox user and a Keycloak account.

    Users are looked up by the immutable ``sub`` claim first, so renaming an
    account in Keycloak re-uses the existing NetBox user instead of creating
    a duplicate.
    """

    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="keycloak_identity",
    )
    sub = models.CharField(max_length=255, unique=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Keycloak identity"
        verbose_name_plural = "Keycloak identities"

    def __str__(self):
        return f"{self.user} ({self.sub})"
