"""
Django settings for config project.

WMS CO LOGISTIC S.A.C.
Backend Django REST Framework
"""

from pathlib import Path
import environ
import os

from django.core.exceptions import ImproperlyConfigured


# =====================================================
# BASE CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# =====================================================
# ENVIRONMENT VARIABLES
# =====================================================

env = environ.Env()

environ.Env.read_env(
    os.path.join(BASE_DIR, ".env")
)


# =====================================================
# SECURITY
# =====================================================

SECRET_KEY = env(
    "SECRET_KEY",
    default="django-insecure-development-key"
)

DEBUG = env.bool(
    "DEBUG",
    default=True
)


ALLOWED_HOSTS = env.list(
    "ALLOWED_HOSTS",
    default=["localhost", "127.0.0.1"],
)

USE_X_FORWARDED_HOST = env.bool("USE_X_FORWARDED_HOST", default=True)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


# =====================================================
# APPLICATIONS
# =====================================================

INSTALLED_APPS = [

    # Django Core
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third Party
    "rest_framework",
    "corsheaders",

    # WMS Modules
    'apps.usuarios',
    'apps.maestros',
    'apps.inventario',
    'apps.servicios',
    'apps.recepciones',
    'apps.pedidos',
    'apps.reportes',

]


# =====================================================
# MIDDLEWARE
# =====================================================

MIDDLEWARE = [

    "corsheaders.middleware.CorsMiddleware",

    "django.middleware.security.SecurityMiddleware",

    "django.contrib.sessions.middleware.SessionMiddleware",

    "django.middleware.common.CommonMiddleware",

    "django.middleware.csrf.CsrfViewMiddleware",

    "django.contrib.auth.middleware.AuthenticationMiddleware",

    "django.contrib.messages.middleware.MessageMiddleware",

    "django.middleware.clickjacking.XFrameOptionsMiddleware",

    "apps.servicios.middleware.TechnicalObservabilityMiddleware",

]


# =====================================================
# URL CONFIGURATION
# =====================================================

ROOT_URLCONF = "config.urls"


# =====================================================
# TEMPLATES
# =====================================================

TEMPLATES = [

    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",

        "DIRS": [],

        "APP_DIRS": True,

        "OPTIONS": {

            "context_processors": [

                "django.template.context_processors.request",

                "django.contrib.auth.context_processors.auth",

                "django.contrib.messages.context_processors.messages",

            ],
        },
    },

]


WSGI_APPLICATION = "config.wsgi.application"

ASGI_APPLICATION = "config.asgi.application"



# =====================================================
# DATABASE
# PostgreSQL
# =====================================================

DATABASES = {

    "default": {

        "ENGINE": "django.db.backends.postgresql",

        "NAME": env(
            "DB_NAME",
            default=""
        ),

        "USER": env(
            "DB_USER",
            default=""
        ),

        "PASSWORD": env(
            "DB_PASSWORD",
            default=""
        ),

        "HOST": env(
            "DB_HOST",
            default=""
        ),

        "PORT": env(
            "DB_PORT",
            default="5432"
        ),

        "OPTIONS": {

            "sslmode": env(
                "DB_SSLMODE",
                default="prefer"
            ),

        },

    }
}



# =====================================================
# PASSWORD VALIDATION
# =====================================================

AUTH_PASSWORD_VALIDATORS = [

    {
        "NAME":
        "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },

    {
        "NAME":
        "django.contrib.auth.password_validation.MinimumLengthValidator",
    },

    {
        "NAME":
        "django.contrib.auth.password_validation.CommonPasswordValidator",
    },

    {
        "NAME":
        "django.contrib.auth.password_validation.NumericPasswordValidator",
    },

]



# =====================================================
# INTERNATIONALIZATION
# =====================================================

LANGUAGE_CODE = "es-pe"


TIME_ZONE = "America/Lima"


USE_I18N = True


USE_TZ = True



# =====================================================
# STATIC FILES
# =====================================================

STATIC_URL = "static/"
STATIC_ROOT = Path(
    env("STATIC_ROOT", default=str(BASE_DIR / "staticfiles"))
)



# =====================================================
# DEFAULT PRIMARY KEY
# =====================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"



# =====================================================
# DJANGO REST FRAMEWORK
# =====================================================

REST_FRAMEWORK = {

    "DEFAULT_AUTHENTICATION_CLASSES": [

        "apps.usuarios.authentication.LocalJWTAuthentication",

    ],

    "DEFAULT_PERMISSION_CLASSES": [

        "rest_framework.permissions.IsAuthenticated",

        "apps.usuarios.authentication.PasswordChangeNotPending",

    ],

    "DEFAULT_THROTTLE_RATES": {

        "auth_login": "10/min",

        "auth_refresh": "30/min",

    },

    "DEFAULT_RENDERER_CLASSES": [

        "rest_framework.renderers.JSONRenderer",

    ],

}


# =====================================================
# LOCAL AUTHENTICATION
# =====================================================

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    # Verifies (and re-hashes on first login) the bcrypt hashes imported
    # from Supabase as "bcrypt$<hash>".
    "django.contrib.auth.hashers.BCryptPasswordHasher",
]

JWT_SIGNING_KEY = env("JWT_SIGNING_KEY", default="")
if not JWT_SIGNING_KEY:
    if DEBUG:
        JWT_SIGNING_KEY = "dev-only-" + SECRET_KEY
    else:
        raise ImproperlyConfigured(
            "JWT_SIGNING_KEY es obligatoria cuando DEBUG=False."
        )

JWT_ISSUER = "wms-cologistic"
JWT_AUDIENCE = "wms"

AUTH_ACCESS_TOKEN_MINUTES = 15
AUTH_REFRESH_TOKEN_HOURS = 8
AUTH_MAX_FAILED_ATTEMPTS = 5
AUTH_LOCK_MINUTES = 15

AUTH_REFRESH_COOKIE_NAME = "wms_refresh"
AUTH_REFRESH_COOKIE_PATH = "/api/auth/"
AUTH_COOKIE_SECURE = env.bool("AUTH_COOKIE_SECURE", default=not DEBUG)



# =====================================================
# CORS - REACT FRONTEND
# =====================================================

FRONTEND_URL = env(
    "FRONTEND_URL",
    default="http://localhost:5173",
).strip()

_default_cors_origins = [
    origin.strip().rstrip("/")
    for origin in FRONTEND_URL.split(",")
    if origin.strip()
]
if DEBUG and _default_cors_origins == ["http://localhost:5173"]:
    _default_cors_origins.append("http://127.0.0.1:5173")

CORS_ALLOWED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in env.list("CORS_ALLOWED_ORIGINS", default=_default_cors_origins)
    if origin.strip()
]

# The refresh token travels in an HttpOnly cookie, so credentials must be
# allowed; CORS_ALLOWED_ORIGINS must therefore list explicit origins.
CORS_ALLOW_CREDENTIALS = True

CSRF_TRUSTED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in env.list("CSRF_TRUSTED_ORIGINS", default=CORS_ALLOWED_ORIGINS)
    if origin.strip()
]


# =====================================================
# PROJECT SETTINGS
# =====================================================

APPEND_SLASH = True

# EP-08 technical operations. Restores remain disabled until an administrator
# explicitly opens a maintenance window through the environment.
TECHNICAL_BACKUP_DIR = Path(
    env("TECHNICAL_BACKUP_DIR", default=str(BASE_DIR / "var" / "backups"))
)
TECHNICAL_ALLOW_RESTORE = env.bool("TECHNICAL_ALLOW_RESTORE", default=False)
TECHNICAL_COMMAND_TIMEOUT = env.int("TECHNICAL_COMMAND_TIMEOUT", default=900)
TECHNICAL_SLOW_REQUEST_MS = env.int("TECHNICAL_SLOW_REQUEST_MS", default=1000)
