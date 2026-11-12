from django.conf import settings
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from . import local_auth
from .models import Permiso, Rol, Usuario
from .permissions import require_application_permission
from .serializers import (
    LoginSerializer,
    PasswordChangeSerializer,
    RoleAssignmentSerializer,
    RoleWriteSerializer,
    UserCreateSerializer,
    UserStatusSerializer,
    UserUpdateSerializer,
)
from .services import (
    build_user_access,
    create_application_user,
    replace_user_roles,
    reset_user_password,
    save_role,
    serialize_role,
    serialize_user,
    set_application_user_status,
    update_application_user,
)


def _no_store(response):
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


def _client_ip(request):
    # Informational only (session list); not used for any security decision.
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    first = forwarded.split(",")[0].strip()
    return (first or request.META.get("REMOTE_ADDR") or "")[:45]


def _user_agent(request):
    return request.META.get("HTTP_USER_AGENT", "")[:255]


def _set_refresh_cookie(response, result):
    response.set_cookie(
        settings.AUTH_REFRESH_COOKIE_NAME,
        result.refresh_token,
        max_age=result.refresh_max_age,
        path=settings.AUTH_REFRESH_COOKIE_PATH,
        secure=settings.AUTH_COOKIE_SECURE,
        httponly=True,
        samesite="Strict",
    )


def _delete_refresh_cookie(response):
    response.delete_cookie(
        settings.AUTH_REFRESH_COOKIE_NAME,
        path=settings.AUTH_REFRESH_COOKIE_PATH,
        samesite="Strict",
    )


def _token_response(result):
    response = Response(
        {
            "access": result.access,
            "expires_in": result.expires_in,
            "debe_cambiar_password": result.must_change_password,
        }
    )
    _set_refresh_cookie(response, result)
    return _no_store(response)


class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_login"

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = local_auth.login(
                serializer.validated_data["correo"],
                serializer.validated_data["password"],
                ip=_client_ip(request),
                user_agent=_user_agent(request),
            )
        except local_auth.InvalidCredentials as exc:
            # No authenticator => DRF would answer 403; a failed login is 401.
            return _no_store(
                Response(
                    {"detail": str(exc.detail), "code": exc.default_code},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            )
        return _token_response(result)


class RefreshView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_refresh"

    def post(self, request):
        raw = request.COOKIES.get(settings.AUTH_REFRESH_COOKIE_NAME)
        try:
            result = local_auth.refresh(
                raw, ip=_client_ip(request), user_agent=_user_agent(request)
            )
        except local_auth.InvalidSession as exc:
            response = Response(
                {"detail": str(exc.detail), "code": exc.default_code},
                status=status.HTTP_401_UNAUTHORIZED,
            )
            _delete_refresh_cookie(response)
            return _no_store(response)
        return _token_response(result)


class LogoutView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        local_auth.logout(request.COOKIES.get(settings.AUTH_REFRESH_COOKIE_NAME))
        response = Response(status=status.HTTP_204_NO_CONTENT)
        _delete_refresh_cookie(response)
        return _no_store(response)


class PasswordChangeView(APIView):
    allow_pending_password_change = True

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = local_auth.change_own_password(
            request.user.profile,
            serializer.validated_data["password_actual"],
            serializer.validated_data["password_nueva"],
            ip=_client_ip(request),
            user_agent=_user_agent(request),
        )
        return _token_response(result)


class CurrentUserView(APIView):
    """Return the application profile and effective access for the session."""

    allow_pending_password_change = True

    def get(self, request):
        return Response(build_user_access(request.user))


class UserListCreateView(APIView):
    def get(self, request):
        require_application_permission(request.user, "usuarios.ver")
        query = Usuario.objects.all().order_by("nombre", "apellido")
        search = request.query_params.get("search", "").strip()
        if search:
            query = query.filter(
                Q(nombre__icontains=search)
                | Q(apellido__icontains=search)
                | Q(correo__icontains=search)
            )
        return Response([serialize_user(user) for user in query[:200]])

    def post(self, request):
        require_application_permission(request.user, "usuarios.crear")
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data["role_ids"]:
            require_application_permission(
                request.user, "usuarios.asignar_roles"
            )
        user = create_application_user(serializer.validated_data)
        return Response(serialize_user(user), status=status.HTTP_201_CREATED)


class UserDetailView(APIView):
    def patch(self, request, user_id):
        require_application_permission(request.user, "usuarios.editar")
        user = get_object_or_404(Usuario, id_usuario=user_id)
        serializer = UserUpdateSerializer(
            data=request.data,
            context={"user_id": user.id_usuario},
        )
        serializer.is_valid(raise_exception=True)
        user = update_application_user(user, serializer.validated_data)
        return Response(serialize_user(user))


class UserRoleAssignmentView(APIView):
    def put(self, request, user_id):
        require_application_permission(request.user, "usuarios.asignar_roles")
        user = get_object_or_404(Usuario, id_usuario=user_id)
        serializer = RoleAssignmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = replace_user_roles(user, serializer.validated_data["role_ids"])
        return Response(serialize_user(user))


class UserStatusView(APIView):
    def patch(self, request, user_id):
        require_application_permission(request.user, "usuarios.desactivar")
        user = get_object_or_404(Usuario, id_usuario=user_id)
        serializer = UserStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        active = serializer.validated_data["estado"]
        if str(user.id_usuario) == str(request.user.id) and not active:
            raise ValidationError(
                {"estado": ["No puedes desactivar tu propia cuenta."]}
            )
        user = set_application_user_status(user, active)
        return Response(serialize_user(user))


class UserPasswordResetView(APIView):
    def post(self, request, user_id):
        require_application_permission(request.user, "usuarios.editar")
        user = get_object_or_404(Usuario, id_usuario=user_id)
        if str(user.id_usuario) == str(request.user.id):
            raise ValidationError(
                {"detail": ["No puedes restablecer tu propia contraseña."]}
            )
        temporary = reset_user_password(user)
        return _no_store(
            Response(
                {
                    "id_usuario": str(user.id_usuario),
                    "password_temporal": temporary,
                }
            )
        )


class RoleListCreateView(APIView):
    def get(self, request):
        require_application_permission(request.user, "roles.ver")
        roles = Rol.objects.all().order_by("nombre")
        return Response([serialize_role(role) for role in roles])

    def post(self, request):
        require_application_permission(request.user, "roles.gestionar")
        serializer = RoleWriteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = save_role(serializer.validated_data)
        return Response(serialize_role(role), status=status.HTTP_201_CREATED)


class RoleDetailView(APIView):
    def patch(self, request, role_id):
        require_application_permission(request.user, "roles.gestionar")
        role = get_object_or_404(Rol, id_rol=role_id)
        serializer = RoleWriteSerializer(
            data=request.data, context={"role_id": role.id_rol}
        )
        serializer.is_valid(raise_exception=True)
        role = save_role(serializer.validated_data, role=role)
        return Response(serialize_role(role))


class PermissionListView(APIView):
    def get(self, request):
        require_application_permission(request.user, "roles.ver")
        permissions = Permiso.objects.filter(estado=True).order_by("nombre")
        return Response(
            list(
                permissions.values(
                    "id_permiso", "nombre", "descripcion", "estado"
                )
            )
        )
