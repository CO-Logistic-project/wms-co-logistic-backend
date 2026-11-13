"""Local authentication: passwords, lockout, JWT access tokens and sessions.

Refresh tokens are opaque random values; only their SHA-256 is stored.

IMPORTANT: a rejection must never be raised from inside ``transaction.atomic()``
when the same block has to persist something (failed-attempt counter, reuse
revocation). The error is captured inside the block and re-raised after the
block has committed.
"""

import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from types import SimpleNamespace

import jwt
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed, ValidationError

from .models import Credencial, Sesion, Usuario


INVALID_CREDENTIALS_MESSAGE = "Correo o contraseña incorrectos."
INVALID_SESSION_MESSAGE = "La sesión no es válida o ha expirado."
ACCESS_TOKEN_TYPE = "access"
JWT_ALGORITHM = "HS256"
# Letters without look-alikes (no I, l, O, 0, 1) for temporary passwords.
_TEMP_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_TEMP_DIGITS = "23456789"


class InvalidCredentials(AuthenticationFailed):
    """Same message for unknown e-mail, wrong password, lock or inactive."""

    default_detail = INVALID_CREDENTIALS_MESSAGE
    default_code = "invalid_credentials"


class InvalidSession(AuthenticationFailed):
    default_detail = INVALID_SESSION_MESSAGE
    default_code = "invalid_session"


@dataclass(frozen=True)
class AuthResult:
    access: str
    expires_in: int
    must_change_password: bool
    refresh_token: str
    refresh_max_age: int


# ---------------------------------------------------------------- passwords


@lru_cache(maxsize=1)
def _dummy_hash():
    return make_password("dummy-password-for-constant-time")


def _safe_check_password(raw, encoded, setter=None):
    try:
        return check_password(raw, encoded, setter=setter)
    except ValueError:
        # bcrypt refuses passwords longer than 72 bytes.
        return False


def check_password_policy(raw, user=None, field="password"):
    """Validate a new password; raises a DRF ValidationError keyed by field."""
    errors = []
    email = getattr(user, "correo", "") or ""
    local_part = email.split("@")[0].lower()

    try:
        validate_password(raw, user=None)
    except DjangoValidationError as exc:
        errors.extend(exc.messages)

    if not re.search(r"[^\W\d_]", raw):
        errors.append("La contraseña debe contener letras.")
    if not re.search(r"\d", raw):
        errors.append("La contraseña debe contener números.")
    if len(local_part) >= 3 and local_part in raw.lower():
        errors.append("La contraseña no puede contener la parte local del correo.")

    if errors:
        raise ValidationError({field: errors})


def generate_temporary_password(user=None, length=14):
    while True:
        chars = [secrets.choice(_TEMP_LETTERS) for _ in range(length - 3)]
        chars += [secrets.choice(_TEMP_DIGITS) for _ in range(3)]
        secrets.SystemRandom().shuffle(chars)
        candidate = "".join(chars)
        try:
            check_password_policy(candidate, user)
        except ValidationError:
            continue
        return candidate


def _store_password(user_id, raw, must_change, now):
    Credencial.objects.update_or_create(
        id_usuario=user_id,
        defaults={
            "password_hash": make_password(raw),
            "debe_cambiar_password": must_change,
            "intentos_fallidos": 0,
            "bloqueado_hasta": None,
            "fecha_actualizacion": now,
        },
    )


def set_password(user_id, raw, must_change, user=None):
    """Create or update the credential and revoke every session."""
    if user is None:
        user = Usuario.objects.filter(id_usuario=user_id).first()
    check_password_policy(raw, user)
    now = timezone.now()
    with transaction.atomic():
        _store_password(user_id, raw, must_change, now)
        revoke_all_sessions(user_id, now)


# ------------------------------------------------------------------- tokens


def issue_access_token(user, must_change_password=False, now=None):
    now = now or timezone.now()
    lifetime = timedelta(minutes=settings.AUTH_ACCESS_TOKEN_MINUTES)
    claims = {
        "sub": str(user.id_usuario),
        "email": user.correo,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + lifetime).timestamp()),
        "typ": ACCESS_TOKEN_TYPE,
        "pwd_change": bool(must_change_password),
    }
    token = jwt.encode(claims, settings.JWT_SIGNING_KEY, algorithm=JWT_ALGORITHM)
    return token, int(lifetime.total_seconds())


def decode_access_token(token):
    try:
        claims = jwt.decode(
            token,
            settings.JWT_SIGNING_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "typ"]},
        )
    except (jwt.PyJWTError, ValueError) as exc:
        raise InvalidSession() from exc
    if claims.get("typ") != ACCESS_TOKEN_TYPE:
        raise InvalidSession()
    return claims


def _hash_token(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _open_session(user, must_change, ip, user_agent, now):
    raw = secrets.token_urlsafe(48)
    lifetime = timedelta(hours=settings.AUTH_REFRESH_TOKEN_HOURS)
    sesion = Sesion.objects.create(
        id_sesion=uuid.uuid4(),
        id_usuario=user.id_usuario,
        token_hash=_hash_token(raw),
        fecha_creacion=now,
        fecha_expiracion=now + lifetime,
        ip=(ip or "")[:45] or None,
        user_agent=(user_agent or "")[:255] or None,
    )
    access, expires_in = issue_access_token(user, must_change, now)
    result = AuthResult(
        access=access,
        expires_in=expires_in,
        must_change_password=bool(must_change),
        refresh_token=raw,
        refresh_max_age=int(lifetime.total_seconds()),
    )
    return result, sesion


def revoke_all_sessions(user_id, now=None):
    now = now or timezone.now()
    return Sesion.objects.filter(
        id_usuario=user_id, fecha_revocacion__isnull=True
    ).update(fecha_revocacion=now)


# ------------------------------------------------------------ authenticate


def _register_failure(credencial, now):
    credencial.intentos_fallidos += 1
    if credencial.intentos_fallidos >= settings.AUTH_MAX_FAILED_ATTEMPTS:
        credencial.bloqueado_hasta = now + timedelta(
            minutes=settings.AUTH_LOCK_MINUTES
        )
    credencial.save(update_fields=["intentos_fallidos", "bloqueado_hasta"])


def _clear_expired_lock(credencial, now):
    if credencial.bloqueado_hasta and credencial.bloqueado_hasta <= now:
        credencial.bloqueado_hasta = None
        credencial.intentos_fallidos = 0
        credencial.save(update_fields=["intentos_fallidos", "bloqueado_hasta"])


def authenticate(email, raw_password, now=None):
    """Return ``(usuario, credencial)`` or raise InvalidCredentials.

    Must run inside a transaction (it locks the credential row) and, when the
    caller wants the failure counter persisted, the caller has to catch the
    exception inside the transaction and re-raise it afterwards (see login).
    """
    now = now or timezone.now()
    normalized = (email or "").strip().lower()
    usuario = Usuario.objects.filter(correo__iexact=normalized).first()
    credencial = None
    if usuario is not None:
        credencial = (
            Credencial.objects.select_for_update()
            .filter(id_usuario=usuario.id_usuario)
            .first()
        )

    if usuario is None or credencial is None:
        _safe_check_password(raw_password, _dummy_hash())
        raise InvalidCredentials()

    _clear_expired_lock(credencial, now)
    if credencial.bloqueado_hasta and credencial.bloqueado_hasta > now:
        _safe_check_password(raw_password, _dummy_hash())
        raise InvalidCredentials()

    def setter(raw):  # re-hash legacy (bcrypt) hashes with the preferred one
        credencial.password_hash = make_password(raw)

    if not _safe_check_password(
        raw_password, credencial.password_hash, setter=setter
    ):
        _register_failure(credencial, now)
        raise InvalidCredentials()

    if not usuario.estado:
        raise InvalidCredentials()

    credencial.intentos_fallidos = 0
    credencial.bloqueado_hasta = None
    credencial.ultimo_acceso = now
    credencial.save(
        update_fields=[
            "password_hash",
            "intentos_fallidos",
            "bloqueado_hasta",
            "ultimo_acceso",
        ]
    )
    return usuario, credencial


def login(email, raw_password, ip=None, user_agent=None):
    now = timezone.now()
    error = None
    result = None
    with transaction.atomic():
        try:
            usuario, credencial = authenticate(email, raw_password, now)
        except InvalidCredentials as exc:
            error = exc  # keep the counter update; raise after the commit
        else:
            result, _ = _open_session(
                usuario, credencial.debe_cambiar_password, ip, user_agent, now
            )
    if error is not None:
        raise error
    return result


# ----------------------------------------------------------------- sessions


def refresh(raw_token, ip=None, user_agent=None):
    now = timezone.now()
    error = None
    result = None
    with transaction.atomic():
        try:
            if not raw_token:
                raise InvalidSession()
            sesion = (
                Sesion.objects.select_for_update()
                .filter(token_hash=_hash_token(raw_token))
                .first()
            )
            if sesion is None:
                raise InvalidSession()
            if sesion.fecha_revocacion is not None:
                if sesion.reemplazada_por is not None:
                    # A rotated token came back: assume it was stolen.
                    revoke_all_sessions(sesion.id_usuario, now)
                raise InvalidSession()
            if sesion.fecha_expiracion <= now:
                raise InvalidSession()

            usuario = Usuario.objects.filter(
                id_usuario=sesion.id_usuario
            ).first()
            credencial = Credencial.objects.filter(
                id_usuario=sesion.id_usuario
            ).first()
            if usuario is None or not usuario.estado or credencial is None:
                raise InvalidSession()

            result, nueva = _open_session(
                usuario, credencial.debe_cambiar_password, ip, user_agent, now
            )
            sesion.fecha_revocacion = now
            sesion.reemplazada_por = nueva.id_sesion
            sesion.save(update_fields=["fecha_revocacion", "reemplazada_por"])
        except InvalidSession as exc:
            error = exc
    if error is not None:
        raise error
    return result


def logout(raw_token):
    if not raw_token:
        return
    Sesion.objects.filter(
        token_hash=_hash_token(raw_token), fecha_revocacion__isnull=True
    ).update(fecha_revocacion=timezone.now())


def change_own_password(user, current_password, new_password, ip=None, user_agent=None):
    """Change the caller's password and open a fresh session."""
    if current_password == new_password:
        raise ValidationError(
            {"password_nueva": ["La nueva contraseña debe ser distinta de la actual."]}
        )
    check_password_policy(new_password, user, field="password_nueva")

    now = timezone.now()
    error = None
    result = None
    with transaction.atomic():
        credencial = (
            Credencial.objects.select_for_update()
            .filter(id_usuario=user.id_usuario)
            .first()
        )
        locked = (
            credencial is not None
            and credencial.bloqueado_hasta is not None
            and credencial.bloqueado_hasta > now
        )
        if (
            credencial is None
            or locked
            or not _safe_check_password(current_password, credencial.password_hash)
        ):
            if credencial is not None and not locked:
                _register_failure(credencial, now)
            error = ValidationError(
                {"password_actual": ["La contraseña actual es incorrecta."]}
            )
        else:
            _store_password(user.id_usuario, new_password, False, now)
            revoke_all_sessions(user.id_usuario, now)
            result, _ = _open_session(user, False, ip, user_agent, now)
    if error is not None:
        raise error
    return result
