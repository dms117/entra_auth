# entra_auth — Django + Microsoft Entra ID Authentication

A self-contained Django app that replaces `django-microsoft-auth` using
**Microsoft's own actively-maintained libraries**:

| Dependency | Why |
|---|---|
| [`msal`](https://pypi.org/project/msal/) | OAuth2 / OIDC token acquisition, PKCE, token-cache management |
| [`requests`](https://pypi.org/project/requests/) | Microsoft Graph API calls |

No dependency on `django-microsoft-auth`, `social-django`, or any other
third-party auth wrapper that could go stale.

---

## Feature overview

- ✅ OAuth2 Authorization Code flow with **PKCE** (most secure option for web apps)
- ✅ Full OpenID Connect user sign-in
- ✅ Token cache persisted in Django session (automatic token refresh)
- ✅ Microsoft Graph `/me` profile sync to Django `User`
- ✅ Entra group → Django group mapping
- ✅ Site-wide login enforcement middleware
- ✅ Per-view decorators (`@entra_login_required`, `@entra_group_required`)
- ✅ Template tags (`{% entra_login_url %}`, `{{ user|is_in_group:"name" }}`)
- ✅ Django system checks validate your configuration at startup
- ✅ Supports confidential clients (web apps) and public clients

---

## Installation

### 1. Copy the app

Place the `entra_auth/` directory anywhere on your Python path — typically
inside your Django project root alongside your other apps.

### 2. Install dependencies

```
pip install msal requests
```

Pin exact versions in your `requirements.txt`:

```
msal>=1.29.0          # Microsoft's own library — actively maintained
requests>=2.32.0      # HTTP for Graph API calls
```

`msal` follows semver and Microsoft commits to backwards compatibility within
major versions, so `>=1.x` is safe to use long-term.

### 3. Register an App in Entra ID (Azure Portal)

1. Go to **Azure Portal → Microsoft Entra ID → App registrations → New registration**
2. Name your app and choose the appropriate **Supported account types**:
   - Single tenant: `Accounts in this organizational directory only`
   - Multi-tenant: `Accounts in any organizational directory`
3. Set the **Redirect URI** to:
   ```
   https://yourdomain.com/entra/callback/
   ```
   (or `http://localhost:8000/entra/callback/` for local development)
4. After registration, go to **Certificates & secrets → New client secret**
   and note it down immediately (shown only once).
5. Note the **Application (client) ID** and **Directory (tenant) ID** from
   the Overview page.
6. Under **API permissions**, confirm `User.Read` (Microsoft Graph) is present.
   Add any additional scopes your app needs and grant admin consent.

### 4. Configure Django settings

```python
# settings.py

INSTALLED_APPS = [
    ...
    "django.contrib.sessions",      # required
    "django.contrib.auth",          # required
    "django.contrib.contenttypes",  # required
    "entra_auth",
]

AUTHENTICATION_BACKENDS = [
    "entra_auth.backends.EntraAuthBackend",
    "django.contrib.auth.backends.ModelBackend",  # keep for admin fallback
]

# Point Django's login redirect at Entra
LOGIN_URL = "/entra/login/"
LOGIN_REDIRECT_URL = "/"            # where to go after successful login

ENTRA_AUTH = {
    # --- Required ---
    "CLIENT_ID":     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "CLIENT_SECRET": "your-client-secret",   # from step 3
    "TENANT_ID":     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",

    # --- Optional (defaults shown) ---
    # "REDIRECT_URI": "https://yourdomain.com/entra/callback/",
    # Omit to auto-build from the incoming request.

    # "SCOPES": ["User.Read"],
    # Add more: ["User.Read", "Mail.Read", "Calendars.Read"]

    # "LOGOUT_REDIRECT_URL": "/",

    # "GRAPH_USER_FIELDS": ["id", "displayName", "mail", "userPrincipalName",
    #                       "givenName", "surname", "jobTitle"],

    # "CREATE_USERS": True,           # auto-create Django users on first login
    # "UPDATE_USER_ON_LOGIN": True,   # re-sync Graph data every login

    # "USERNAME_FIELD": "email",      # or "oid" to use Entra object ID

    # Group mapping: Entra group object-ID → Django group name
    # "GROUPS_MAP": {
    #     "aad-group-object-id-1": "django-group-name-1",
    #     "aad-group-object-id-2": "django-group-name-2",
    # },
}
```

> **Security**: Store `CLIENT_SECRET` in an environment variable, never in
> source code.  Use `python-decouple`, `django-environ`, or plain `os.environ`.

### 5. Add URL patterns

```python
# urls.py (root)
from django.urls import include, path

urlpatterns = [
    ...
    path("entra/", include("entra_auth.urls")),
]
```

### 6. Run system checks

```
python manage.py check
```

Fix any `entra_auth.E*` errors before proceeding.

### 7. (Optional) Enable site-wide login enforcement

To require login on **every** URL by default (and selectively exempt public
pages), add the middleware **after** `AuthenticationMiddleware`:

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "entra_auth.middleware.EntraLoginRequiredMiddleware",   # ← add here
    "django.contrib.messages.middleware.MessageMiddleware",
    ...
]
```

---

## Usage

### Protect a single view

```python
from entra_auth.decorators import entra_login_required, entra_group_required

@entra_login_required
def my_view(request):
    ...

# Class-based views
from django.utils.decorators import method_decorator

@method_decorator(entra_login_required, name="dispatch")
class MyView(View):
    ...
```

### Restrict to a Django group

```python
@entra_group_required("finance-team")
def finance_report(request):
    ...

# Multiple groups — user needs to be in at least one
@entra_group_required("finance-team", "admins")
def sensitive_view(request):
    ...

# Raise 403 instead of redirecting to login
@entra_group_required("admins", raise_exception=True)
def admin_view(request):
    ...
```

### Exempt a view from the site-wide middleware

```python
from entra_auth.decorators import entra_login_not_required

@entra_login_not_required
def health_check(request):
    return HttpResponse("ok")
```

### Template tags

```html
{% load entra_tags %}

<a href="{% entra_login_url %}">Sign in with Microsoft</a>
<a href="{% entra_logout_url %}">Sign out</a>

{# Redirect back after login #}
<a href="{% entra_login_url request.get_full_path %}">Sign in</a>

{# Group check in template #}
{% if request.user|is_in_group:"finance-team" %}
    <a href="/finance/">Finance dashboard</a>
{% endif %}
```

### Calling Microsoft Graph from a view

```python
from entra_auth.msal_client import acquire_token_silent
from entra_auth.graph import graph_get, GraphError

def my_graph_view(request):
    result = acquire_token_silent(request)
    if not result or "access_token" not in result:
        # Token expired and couldn't refresh — re-authenticate
        return redirect(f"/entra/login/?next={request.path}")

    try:
        profile = graph_get(result["access_token"], "/me")
    except GraphError as e:
        return HttpResponse(f"Graph error: {e}", status=502)

    return JsonResponse(profile)
```

---

## Multi-tenant setup

Change `TENANT_ID` to `"common"` or `"organizations"`:

```python
ENTRA_AUTH = {
    "CLIENT_ID": "...",
    "CLIENT_SECRET": "...",
    "TENANT_ID": "organizations",   # any work/school account
}
```

Remember to update the App Registration's **Supported account types** in the
Azure Portal to match.

---

## Group mapping

1. In **Entra ID → App registrations → your app → Token configuration**,
   add a **Groups claim** (choose "Security groups" or "All groups").
2. Note each group's **Object ID** from
   **Entra ID → Groups → [group] → Overview**.
3. Configure the mapping:

```python
ENTRA_AUTH = {
    ...
    "GROUPS_MAP": {
        "11111111-aaaa-bbbb-cccc-dddddddddddd": "finance",
        "22222222-aaaa-bbbb-cccc-dddddddddddd": "engineering",
    },
}
```

When a user's group count exceeds 200, Entra omits groups from the token.
The app automatically falls back to a Graph `/me/memberOf` call in that case.

---

## Migrating from django-microsoft-auth

| django-microsoft-auth | entra_auth |
|---|---|
| `MicrosoftAuthenticationBackend` | `entra_auth.backends.EntraAuthBackend` |
| `MicrosoftAuthMiddleware` | `entra_auth.middleware.EntraLoginRequiredMiddleware` |
| `microsoft_auth/urls.py` | `entra_auth.urls` |
| `MICROSOFT_AUTH_CLIENT_ID` | `ENTRA_AUTH["CLIENT_ID"]` |
| `MICROSOFT_AUTH_CLIENT_SECRET` | `ENTRA_AUTH["CLIENT_SECRET"]` |
| `MICROSOFT_AUTH_TENANT_ID` | `ENTRA_AUTH["TENANT_ID"]` |

Steps:
1. Remove `microsoft_auth` from `INSTALLED_APPS` and `AUTHENTICATION_BACKENDS`.
2. Remove `microsoft_auth.urls` from your URLconf.
3. Add `entra_auth` per the instructions above.
4. Run `python manage.py check` and resolve any issues.
5. Users are matched by `username` — as long as your existing usernames match
   `preferred_username` (email) from Entra, they will be linked automatically.

---

## Security notes

- The Authorization Code + PKCE flow is used automatically — the implicit
  grant flow (deprecated) is never used.
- `CLIENT_SECRET` is never exposed to the browser.
- CSRF is handled by MSAL's `state` parameter in the auth-code flow.
- The token cache is stored in the Django session (server-side by default).
  Use a server-side session backend (database or cache) in production rather
  than cookie-based sessions.
- Always use HTTPS in production; Entra will refuse non-HTTPS redirect URIs
  except for `localhost`.

---

## Directory structure

```
entra_auth/
├── __init__.py
├── apps.py             ← AppConfig
├── backends.py         ← Django auth backend
├── checks.py           ← startup validation
├── conf.py             ← settings proxy
├── decorators.py       ← @entra_login_required etc.
├── graph.py            ← Microsoft Graph helper
├── middleware.py       ← site-wide login enforcement
├── msal_client.py      ← MSAL wrapper + session token cache
├── urls.py             ← login / callback / logout URLs
├── views.py            ← the three auth views
├── migrations/
│   └── __init__.py     ← no models, no migrations needed
└── templatetags/
    ├── __init__.py
    └── entra_tags.py   ← {% load entra_tags %}
```
