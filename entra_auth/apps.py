from django.apps import AppConfig


class EntraAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "entra_auth"
    verbose_name = "Entra ID Authentication"

    def ready(self):
        from . import checks  # noqa: F401 — register system checks
