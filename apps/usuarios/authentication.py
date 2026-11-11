import logging
from dataclasses import dataclass

from django.db import DatabaseError
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import APIException, AuthenticationFailed, PermissionDenied
from rest_framework.permissions import BasePermission

from .local_auth import decode_access_token
from .models import Usuario


logger = logging.getLogger(__name__)


class AuthenticationServiceUnavailable(APIException):
    status_code = 503
    default_detail = "No fue posible validar la sesión. Inténtalo nuevamente."
    default_code = "authentication_unavailable"


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    id: str
    email: str
    claims: dict
    profile: Usuario

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    @property
    def must_change_password(self):
        return bool(self.claims.get("pwd_change"))


class LocalJWTAuthentication(BaseAuthentication):
    """Validate the HS256 access token locally (no network access)."""

    keyword = "Bearer"

    def authenticate(self, request):
        authorization = get_authorization_header(request).split()

        if not authorization:
            return None

        if authorization[0].decode("ascii", errors="ignore").lower() != "bearer":
            return None

        if len(authorization) != 2:
            raise AuthenticationFailed("Encabezado de autorización inválido.")

        try:
            token = authorization[1].decode("utf-8")
        except UnicodeError as exc:
            raise AuthenticationFailed(
                "Encabezado de autorización inválido."
            ) from exc

        claims = decode_access_token(token)
        user_id = claims.get("sub")

        try:
            profile = Usuario.objects.filter(id_usuario=user_id).first()
        except (DatabaseError, ValueError) as exc:
            logger.exception("Application user lookup failed")
            raise AuthenticationServiceUnavailable() from exc

        if profile is None or not profile.estado:
            raise AuthenticationFailed(
                "La cuenta no está habilitada para acceder al sistema."
            )

        principal = AuthenticatedPrincipal(
            id=str(profile.id_usuario),
            email=claims.get("email") or profile.correo,
            claims=claims,
            profile=profile,
        )
        return principal, token

    def authenticate_header(self, request):
        return self.keyword


class PasswordChangeNotPending(BasePermission):
    """Block every endpoint while the user must change a temporary password.

    Views that must stay reachable set ``allow_pending_password_change = True``.
    """

    def has_permission(self, request, view):
        if getattr(view, "allow_pending_password_change", False):
            return True
        if getattr(request.user, "must_change_password", False):
            raise PermissionDenied(
                detail={
                    "detail": "Debes cambiar tu contraseña antes de continuar.",
                    "code": "password_change_required",
                },
                code="password_change_required",
            )
        return True
