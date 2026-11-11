"""Tests for local authentication.

The WMS tables are ``managed = False`` and live in a pre-existing PostgreSQL
schema, so these tests run without a database: Usuario / Credencial / Sesion
managers are replaced by a tiny in-memory store and ``transaction.atomic`` by
a recorder that remembers whether an exception travelled through it (a raised
rejection inside the block would roll the failed-attempt counter back).
"""

import uuid
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import bcrypt
import jwt
from django.contrib.auth.hashers import PBKDF2PasswordHasher, check_password, make_password
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.test import APIRequestFactory, force_authenticate

from . import local_auth
from .authentication import AuthenticatedPrincipal, LocalJWTAuthentication
from .local_auth import InvalidCredentials, InvalidSession
from .models import Credencial, Sesion, Usuario
from .permissions import require_application_permission
from .services import (
    build_user_access,
    create_application_user,
    reset_user_password,
    set_application_user_status,
)
from .views import (
    CurrentUserView,
    LoginView,
    LogoutView,
    PasswordChangeView,
    RefreshView,
    UserListCreateView,
    UserPasswordResetView,
    UserStatusView,
)


KEY = "test-signing-key-with-more-than-32-bytes"
PASSWORD = "Almacen-Seguro-7431"


class FastPBKDF2PasswordHasher(PBKDF2PasswordHasher):
    iterations = 1000


FAST_HASHERS = [
    "apps.usuarios.tests.FastPBKDF2PasswordHasher",
    "django.contrib.auth.hashers.BCryptPasswordHasher",
]


# ------------------------------------------------------------ in-memory ORM


class Row(SimpleNamespace):
    def save(self, update_fields=None):
        pass


def _match(row, key, value):
    if key.endswith("__iexact"):
        return str(getattr(row, key[:-8], "")).lower() == str(value).lower()
    if key.endswith("__isnull"):
        return (getattr(row, key[:-8], None) is None) == value
    return str(getattr(row, key, None)) == str(value)


class FakeQuerySet:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **kwargs):
        return FakeQuerySet(
            [r for r in self.rows if all(_match(r, k, v) for k, v in kwargs.items())]
        )

    def first(self):
        return self.rows[0] if self.rows else None

    def exists(self):
        return bool(self.rows)

    def count(self):
        return len(self.rows)

    def update(self, **kwargs):
        for row in self.rows:
            for key, value in kwargs.items():
                setattr(row, key, value)
        return len(self.rows)


class FakeManager(FakeQuerySet):
    def __init__(self, defaults=None):
        super().__init__([])
        self.defaults = defaults or {}

    def select_for_update(self):
        return self

    def create(self, **kwargs):
        row = Row(**{**self.defaults, **kwargs})
        self.rows.append(row)
        return row

    def update_or_create(self, defaults=None, **lookup):
        row = self.filter(**lookup).first()
        if row is None:
            return self.create(**lookup, **(defaults or {})), True
        for key, value in (defaults or {}).items():
            setattr(row, key, value)
        return row, False


class RecordingAtomic:
    def __init__(self):
        self.exits = []

    @contextmanager
    def atomic(self):
        try:
            yield
        except BaseException as exc:
            self.exits.append(exc)
            raise
        else:
            self.exits.append(None)


@override_settings(JWT_SIGNING_KEY=KEY, PASSWORD_HASHERS=FAST_HASHERS)
class StoreTestCase(SimpleTestCase):
    def setUp(self):
        cache.clear()
        local_auth._dummy_hash.cache_clear()
        self.addCleanup(local_auth._dummy_hash.cache_clear)
        self.usuarios = FakeManager()
        self.credenciales = FakeManager()
        self.sesiones = FakeManager({"fecha_revocacion": None, "reemplazada_por": None})
        self.atomic = RecordingAtomic()
        for target, attr, fake in [
            (Usuario, "objects", self.usuarios),
            (Credencial, "objects", self.credenciales),
            (Sesion, "objects", self.sesiones),
        ]:
            patcher = patch.object(target, attr, fake)
            patcher.start()
            self.addCleanup(patcher.stop)
        for module in ("local_auth", "services"):
            patcher = patch(
                f"apps.usuarios.{module}.transaction", SimpleNamespace(atomic=self.atomic.atomic)
            )
            patcher.start()
            self.addCleanup(patcher.stop)
        self.factory = APIRequestFactory()

    def add_user(self, email="operador@empresa.com", password=PASSWORD,
                 estado=True, must_change=False, encoded=None):
        user = self.usuarios.create(
            id_usuario=uuid.uuid4(), nombre="Ana", apellido="Torres",
            correo=email, estado=estado,
        )
        self.credenciales.create(
            id_usuario=user.id_usuario,
            password_hash=encoded or make_password(password),
            debe_cambiar_password=must_change,
            intentos_fallidos=0, bloqueado_hasta=None, ultimo_acceso=None,
        )
        return user

    def credential_of(self, user):
        return self.credenciales.filter(id_usuario=user.id_usuario).first()

    def active_sessions(self, user):
        return self.sesiones.filter(
            id_usuario=user.id_usuario, fecha_revocacion__isnull=True
        ).rows

    def assert_no_exception_crossed_atomic(self):
        self.assertTrue(self.atomic.exits)
        self.assertTrue(all(exit_ is None for exit_ in self.atomic.exits))

    def bearer(self, token):
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def token_for(self, user, pwd_change=False):
        return local_auth.issue_access_token(user, pwd_change)[0]


# -------------------------------------------------------------------- login


class LoginTests(StoreTestCase):
    def test_correct_login_returns_tokens_and_opens_a_session(self):
        user = self.add_user()

        result = local_auth.login("Operador@Empresa.com", PASSWORD, ip="10.0.0.1")

        claims = local_auth.decode_access_token(result.access)
        self.assertEqual(claims["sub"], str(user.id_usuario))
        self.assertEqual(claims["typ"], "access")
        self.assertFalse(claims["pwd_change"])
        self.assertEqual(result.expires_in, 15 * 60)
        session = self.active_sessions(user)[0]
        self.assertEqual(len(session.token_hash), 64)
        self.assertNotIn(result.refresh_token, session.token_hash)
        self.assertEqual(session.ip, "10.0.0.1")
        self.assertIsNotNone(self.credential_of(user).ultimo_acceso)

    def test_wrong_password_is_rejected_and_counted(self):
        user = self.add_user()

        with self.assertRaises(InvalidCredentials):
            local_auth.login(user.correo, "otra-clave-1")

        self.assertEqual(self.credential_of(user).intentos_fallidos, 1)
        self.assert_no_exception_crossed_atomic()

    def test_unknown_email_gets_the_same_message_and_runs_a_dummy_check(self):
        user = self.add_user()
        with self.assertRaises(InvalidCredentials) as wrong:
            local_auth.login(user.correo, "otra-clave-1")

        with patch.object(local_auth, "_safe_check_password", wraps=local_auth._safe_check_password) as check:
            with self.assertRaises(InvalidCredentials) as unknown:
                local_auth.login("nadie@empresa.com", "otra-clave-1")

        self.assertEqual(str(wrong.exception.detail), str(unknown.exception.detail))
        self.assertEqual(wrong.exception.default_code, unknown.exception.default_code)
        check.assert_called_once()
        self.assertTrue(check_password("dummy-password-for-constant-time", check.call_args.args[1]))

    def test_account_locks_on_fifth_failure_and_counter_is_persisted(self):
        user = self.add_user()

        for _ in range(5):
            with self.assertRaises(InvalidCredentials):
                local_auth.login(user.correo, "otra-clave-1")

        credential = self.credential_of(user)
        self.assertEqual(credential.intentos_fallidos, 5)
        self.assertGreater(credential.bloqueado_hasta, timezone.now() + timedelta(minutes=14))
        # The rejection was raised only after leaving transaction.atomic().
        self.assert_no_exception_crossed_atomic()
        # Even the right password is refused while locked, with the same message.
        with self.assertRaises(InvalidCredentials):
            local_auth.login(user.correo, PASSWORD)
        self.assertEqual(self.active_sessions(user), [])

    def test_expired_lock_is_cleared_on_next_attempt(self):
        user = self.add_user()
        credential = self.credential_of(user)
        credential.intentos_fallidos = 5
        credential.bloqueado_hasta = timezone.now() - timedelta(seconds=1)

        local_auth.login(user.correo, PASSWORD)

        self.assertEqual(credential.intentos_fallidos, 0)
        self.assertIsNone(credential.bloqueado_hasta)

    def test_inactive_user_is_rejected(self):
        user = self.add_user(estado=False)

        with self.assertRaises(InvalidCredentials):
            local_auth.login(user.correo, PASSWORD)

        self.assertEqual(self.active_sessions(user), [])

    def test_imported_supabase_bcrypt_hash_is_valid_and_rehashed_to_pbkdf2(self):
        supabase_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(4)).decode()
        user = self.add_user(encoded="bcrypt$" + supabase_hash)

        local_auth.login(user.correo, PASSWORD)

        self.assertTrue(self.credential_of(user).password_hash.startswith("pbkdf2_sha256$"))
        local_auth.login(user.correo, PASSWORD)  # still works after the re-hash

    def test_temporary_login_flags_the_token(self):
        user = self.add_user(must_change=True)

        result = local_auth.login(user.correo, PASSWORD)

        self.assertTrue(result.must_change_password)
        self.assertTrue(local_auth.decode_access_token(result.access)["pwd_change"])


# ------------------------------------------------------------------ refresh


class RefreshAndLogoutTests(StoreTestCase):
    def test_refresh_rotates_the_token(self):
        user = self.add_user()
        first = local_auth.login(user.correo, PASSWORD)

        second = local_auth.refresh(first.refresh_token)

        self.assertNotEqual(first.refresh_token, second.refresh_token)
        old = self.sesiones.filter(token_hash=local_auth._hash_token(first.refresh_token)).first()
        self.assertIsNotNone(old.fecha_revocacion)
        self.assertIsNotNone(old.reemplazada_por)
        self.assertEqual(len(self.active_sessions(user)), 1)
        local_auth.decode_access_token(second.access)

    def test_reused_refresh_token_revokes_every_session_of_the_user(self):
        user = self.add_user()
        first = local_auth.login(user.correo, PASSWORD)
        other_device = local_auth.login(user.correo, PASSWORD)
        second = local_auth.refresh(first.refresh_token)

        with self.assertRaises(InvalidSession):
            local_auth.refresh(first.refresh_token)  # replay of a rotated token

        self.assertEqual(self.active_sessions(user), [])
        self.assert_no_exception_crossed_atomic()
        for token in (second.refresh_token, other_device.refresh_token):
            with self.assertRaises(InvalidSession):
                local_auth.refresh(token)

    def test_unknown_missing_and_expired_tokens_are_rejected(self):
        user = self.add_user()
        result = local_auth.login(user.correo, PASSWORD)
        self.active_sessions(user)[0].fecha_expiracion = timezone.now() - timedelta(seconds=1)

        for token in (None, "", "desconocido", result.refresh_token):
            with self.assertRaises(InvalidSession):
                local_auth.refresh(token)

    def test_refresh_of_a_deactivated_user_is_rejected(self):
        user = self.add_user()
        result = local_auth.login(user.correo, PASSWORD)
        user.estado = False

        with self.assertRaises(InvalidSession):
            local_auth.refresh(result.refresh_token)

    def test_logout_revokes_the_session(self):
        user = self.add_user()
        result = local_auth.login(user.correo, PASSWORD)

        local_auth.logout(result.refresh_token)

        self.assertEqual(self.active_sessions(user), [])
        with self.assertRaises(InvalidSession):
            local_auth.refresh(result.refresh_token)
        local_auth.logout(result.refresh_token)  # idempotent
        local_auth.logout(None)

    def test_login_view_sets_a_strict_httponly_cookie_scoped_to_auth(self):
        user = self.add_user()
        request = self.factory.post(
            "/api/auth/login/", {"correo": user.correo, "password": PASSWORD}, format="json"
        )

        response = LoginView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.data), {"access", "expires_in", "debe_cambiar_password"})
        self.assertEqual(response["Cache-Control"], "no-store")
        cookie = response.cookies["wms_refresh"]
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(cookie["path"], "/api/auth/")
        self.assertEqual(cookie["max-age"], 8 * 3600)
        self.assertNotIn("refresh", response.data)

    def test_login_view_error_is_401_with_generic_message(self):
        request = self.factory.post(
            "/api/auth/login/", {"correo": "x@y.com", "password": "abc"}, format="json"
        )

        response = LoginView.as_view()(request)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["detail"], local_auth.INVALID_CREDENTIALS_MESSAGE)

    def test_refresh_view_rotates_via_cookie_and_clears_it_when_invalid(self):
        user = self.add_user()
        first = local_auth.login(user.correo, PASSWORD)
        self.factory.cookies["wms_refresh"] = first.refresh_token

        ok = RefreshView.as_view()(self.factory.post("/api/auth/refresh/"))
        replay = RefreshView.as_view()(self.factory.post("/api/auth/refresh/"))

        self.assertEqual(ok.status_code, 200)
        self.assertNotEqual(ok.cookies["wms_refresh"].value, first.refresh_token)
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.cookies["wms_refresh"].value, "")
        self.assertEqual(replay.cookies["wms_refresh"]["max-age"], 0)
        self.assertEqual(replay["Cache-Control"], "no-store")

    def test_logout_view_revokes_clears_cookie_and_returns_204(self):
        user = self.add_user()
        result = local_auth.login(user.correo, PASSWORD)
        self.factory.cookies["wms_refresh"] = result.refresh_token

        response = LogoutView.as_view()(self.factory.post("/api/auth/logout/"))

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.cookies["wms_refresh"]["max-age"], 0)
        self.assertEqual(self.active_sessions(user), [])


# ------------------------------------------------------------- access token


class AccessTokenTests(StoreTestCase):
    def claims(self, **overrides):
        now = timezone.now()
        claims = {
            "sub": str(uuid.uuid4()), "email": "a@b.com", "iss": "wms-cologistic",
            "aud": "wms", "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "typ": "access", "pwd_change": False,
        }
        claims.update(overrides)
        return claims

    def test_valid_token_is_accepted(self):
        claims = self.claims()
        token = jwt.encode(claims, KEY, algorithm="HS256")

        self.assertEqual(local_auth.decode_access_token(token)["sub"], claims["sub"])

    def test_tokens_with_wrong_key_audience_issuer_type_or_expiry_are_rejected(self):
        bad = [
            jwt.encode(self.claims(), "otra-llave-de-mas-de-32-bytes-aaaa", algorithm="HS256"),
            jwt.encode(self.claims(aud="authenticated"), KEY, algorithm="HS256"),
            jwt.encode(self.claims(iss="otro"), KEY, algorithm="HS256"),
            jwt.encode(self.claims(typ="refresh"), KEY, algorithm="HS256"),
            jwt.encode({k: v for k, v in self.claims().items() if k != "typ"}, KEY, algorithm="HS256"),
            jwt.encode(self.claims(exp=int(timezone.now().timestamp()) - 60), KEY, algorithm="HS256"),
            jwt.encode(self.claims(), KEY, algorithm="HS512"),
            "no-es-un-jwt",
        ]
        for token in bad:
            with self.subTest(token=token[:20]):
                with self.assertRaises(AuthenticationFailed):
                    local_auth.decode_access_token(token)

    def test_authentication_class_returns_principal_for_active_user(self):
        user = self.add_user()
        request = self.factory.get("/x", **self.bearer(self.token_for(user)))

        principal, token = LocalJWTAuthentication().authenticate(request)

        self.assertEqual(principal.id, str(user.id_usuario))
        self.assertEqual(principal.profile, user)
        self.assertFalse(principal.must_change_password)

    def test_authentication_class_rejects_inactive_user_and_other_schemes(self):
        user = self.add_user(estado=False)
        request = self.factory.get("/x", **self.bearer(self.token_for(user)))

        with self.assertRaises(AuthenticationFailed):
            LocalJWTAuthentication().authenticate(request)
        self.assertIsNone(LocalJWTAuthentication().authenticate(self.factory.get("/x")))


# --------------------------------------------------------- pending password


class PendingPasswordChangeTests(StoreTestCase):
    def test_pending_token_gets_403_with_code_on_protected_endpoints(self):
        user = self.add_user(must_change=True)
        request = self.factory.get("/api/users/", **self.bearer(self.token_for(user, True)))

        response = UserListCreateView.as_view()(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "password_change_required")

    def test_pending_token_can_still_reach_me(self):
        user = self.add_user(must_change=True)
        request = self.factory.get("/api/auth/me/", **self.bearer(self.token_for(user, True)))

        with patch("apps.usuarios.views.build_user_access", return_value={"ok": True}):
            response = CurrentUserView.as_view()(request)

        self.assertEqual(response.status_code, 200)

    def test_pending_token_can_change_the_password_and_gets_a_fresh_session(self):
        user = self.add_user(must_change=True)
        old = local_auth.login(user.correo, PASSWORD)
        request = self.factory.post(
            "/api/auth/password/change/",
            {"password_actual": PASSWORD, "password_nueva": "Nueva-Clave-9182"},
            format="json", **self.bearer(old.access),
        )

        response = PasswordChangeView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["debe_cambiar_password"])
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertFalse(local_auth.decode_access_token(response.data["access"])["pwd_change"])
        self.assertEqual(len(self.active_sessions(user)), 1)
        with self.assertRaises(InvalidSession):
            local_auth.refresh(old.refresh_token)

    def test_normal_token_is_not_blocked(self):
        user = self.add_user()
        request = self.factory.get("/api/users/", **self.bearer(self.token_for(user)))

        with patch("apps.usuarios.views.require_application_permission", side_effect=PermissionDenied()):
            response = UserListCreateView.as_view()(request)

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("code", response.data)  # plain permission error, not the pending-change one


# --------------------------------------------------------- password changes


class PasswordTests(StoreTestCase):
    def test_change_own_password(self):
        user = self.add_user(must_change=True)
        old = local_auth.login(user.correo, PASSWORD)

        result = local_auth.change_own_password(user, PASSWORD, "Nueva-Clave-9182")

        credential = self.credential_of(user)
        self.assertFalse(credential.debe_cambiar_password)
        self.assertTrue(check_password("Nueva-Clave-9182", credential.password_hash))
        self.assertFalse(result.must_change_password)
        self.assertEqual(len(self.active_sessions(user)), 1)
        with self.assertRaises(InvalidSession):
            local_auth.refresh(old.refresh_token)
        local_auth.login(user.correo, "Nueva-Clave-9182")

    def test_change_own_password_rejects_wrong_current_and_counts_it(self):
        from rest_framework.exceptions import ValidationError

        user = self.add_user()

        with self.assertRaises(ValidationError) as ctx:
            local_auth.change_own_password(user, "incorrecta-123", "Nueva-Clave-9182")

        self.assertIn("password_actual", ctx.exception.detail)
        self.assertEqual(self.credential_of(user).intentos_fallidos, 1)
        self.assert_no_exception_crossed_atomic()

    def test_policy_rejects_weak_passwords(self):
        from rest_framework.exceptions import ValidationError

        user = SimpleNamespace(correo="operador@empresa.com", nombre="Ana", apellido="Torres")
        for weak in ("corta1", "12345678901", "sololetrasaqui", "password123",
                     "xxOperador-2025"):
            with self.subTest(weak=weak):
                with self.assertRaises(ValidationError):
                    local_auth.check_password_policy(weak, user)
        local_auth.check_password_policy("Almacen-Seguro-7431", user)

    def test_temporary_passwords_pass_the_policy(self):
        user = SimpleNamespace(correo="operador@empresa.com", nombre="Ana", apellido="Torres")
        for _ in range(20):
            local_auth.check_password_policy(local_auth.generate_temporary_password(user), user)


# -------------------------------------------------------- administration


class AdministrationTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.admin = SimpleNamespace(id=str(uuid.uuid4()), is_authenticated=True)

    def test_admin_reset_returns_temporary_password_and_forces_change(self):
        user = self.add_user()
        session = local_auth.login(user.correo, PASSWORD)
        request = self.factory.post(f"/api/users/{user.id_usuario}/password/reset/")
        force_authenticate(request, user=self.admin, token="t")

        with patch("apps.usuarios.views.require_application_permission") as require, \
                patch("apps.usuarios.views.get_object_or_404", return_value=user):
            response = UserPasswordResetView.as_view()(request, user_id=user.id_usuario)

        require.assert_called_once_with(self.admin, "usuarios.editar")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response.data["id_usuario"], str(user.id_usuario))
        temporary = response.data["password_temporal"]
        self.assertTrue(self.credential_of(user).debe_cambiar_password)
        self.assertTrue(local_auth.login(user.correo, temporary).must_change_password)
        with self.assertRaises(InvalidSession):
            local_auth.refresh(session.refresh_token)
        with self.assertRaises(InvalidCredentials):
            local_auth.login(user.correo, PASSWORD)

    def test_admin_cannot_reset_own_password(self):
        user = self.add_user()
        self.admin.id = str(user.id_usuario)
        request = self.factory.post(f"/api/users/{user.id_usuario}/password/reset/")
        force_authenticate(request, user=self.admin, token="t")

        with patch("apps.usuarios.views.require_application_permission"), \
                patch("apps.usuarios.views.get_object_or_404", return_value=user), \
                patch("apps.usuarios.views.reset_user_password") as reset:
            response = UserPasswordResetView.as_view()(request, user_id=user.id_usuario)

        self.assertEqual(response.status_code, 400)
        reset.assert_not_called()

    def test_reset_requires_the_edit_permission(self):
        user = self.add_user()
        request = self.factory.post(f"/api/users/{user.id_usuario}/password/reset/")
        force_authenticate(request, user=self.admin, token="t")

        with patch("apps.usuarios.views.require_application_permission", side_effect=PermissionDenied()):
            response = UserPasswordResetView.as_view()(request, user_id=user.id_usuario)

        self.assertEqual(response.status_code, 403)

    def test_service_reset_user_password(self):
        user = self.add_user()

        temporary = reset_user_password(user)

        self.assertTrue(check_password(temporary, self.credential_of(user).password_hash))

    def test_deactivating_revokes_every_session(self):
        user = self.add_user()
        user.save = Mock()
        local_auth.login(user.correo, PASSWORD)
        local_auth.login(user.correo, PASSWORD)

        set_application_user_status(user, False)

        self.assertFalse(user.estado)
        self.assertEqual(self.active_sessions(user), [])
        user.save.assert_called_once_with(update_fields=["estado", "fecha_actualizacion"])

    def test_create_user_stores_a_must_change_credential(self):
        payload = {
            "nombre": "Luis", "apellido": "Rojas", "correo": "luis@empresa.com",
            "password": "Inicial-Clave-5521", "role_ids": [3],
        }
        with patch("apps.usuarios.services.UsuarioRol.objects.bulk_create") as roles:
            user = create_application_user(payload)

        roles.assert_called_once()
        self.assertIsInstance(user.id_usuario, uuid.UUID)
        credential = self.credential_of(user)
        self.assertTrue(credential.debe_cambiar_password)
        self.assertTrue(check_password("Inicial-Clave-5521", credential.password_hash))
        self.assertTrue(local_auth.login("luis@empresa.com", "Inicial-Clave-5521").must_change_password)

    def test_create_user_with_weak_password_returns_400(self):
        request = self.factory.post(
            "/api/users/",
            {"nombre": "Luis", "apellido": "Rojas", "correo": "luis@empresa.com",
             "password": "12345678"},
            format="json",
        )
        force_authenticate(request, user=self.admin, token="t")

        with patch("apps.usuarios.views.require_application_permission"), \
                patch("apps.usuarios.views.create_application_user") as create:
            response = UserListCreateView.as_view()(request)

        self.assertEqual(response.status_code, 400)
        self.assertIn("password", response.data)
        create.assert_not_called()

    def test_build_user_access_reports_pending_password_change(self):
        user = self.add_user()
        principal = AuthenticatedPrincipal(
            id=str(user.id_usuario), email=user.correo, claims={"pwd_change": True}, profile=user
        )

        with patch("apps.usuarios.services.get_user_roles", return_value=[]), \
                patch("apps.usuarios.services.RolPermiso.objects.filter"), \
                patch("apps.usuarios.services.Permiso.objects.filter") as permisos:
            permisos.return_value.order_by.return_value.values_list.return_value.distinct.return_value = []
            data = build_user_access(principal)

        self.assertTrue(data["debe_cambiar_password"])


# ------------------------------------------------- existing permission tests


class ApplicationAuthorizationTests(SimpleTestCase):
    @patch("apps.usuarios.permissions.user_has_permission", return_value=True)
    def test_required_application_permission_allows_authorized_user(self, has_permission):
        principal = SimpleNamespace(id="user-id")

        require_application_permission(principal, "usuarios.ver")

        has_permission.assert_called_once_with(principal, "usuarios.ver")

    @patch("apps.usuarios.permissions.user_has_permission", return_value=False)
    def test_required_application_permission_rejects_unauthorized_user(self, _):
        with self.assertRaises(PermissionDenied):
            require_application_permission(SimpleNamespace(id="user-id"), "roles.ver")


class CurrentUserViewTests(SimpleTestCase):
    def test_me_rejects_anonymous_request(self):
        response = CurrentUserView.as_view()(APIRequestFactory().get("/api/auth/me/"))

        self.assertEqual(response.status_code, 401)


class UserStatusViewTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.principal = SimpleNamespace(
            id="3f09a7b9-e9fd-48dc-b134-20a4f909e629",
            is_authenticated=True,
        )

    @patch("apps.usuarios.views.set_application_user_status")
    @patch("apps.usuarios.views.require_application_permission")
    @patch("apps.usuarios.views.get_object_or_404")
    def test_administrator_cannot_deactivate_own_account(
        self, get_user, _, set_status
    ):
        get_user.return_value = SimpleNamespace(
            id_usuario=self.principal.id, estado=True
        )
        request = self.factory.patch(
            f"/api/users/{self.principal.id}/status/",
            {"estado": False},
            format="json",
        )
        force_authenticate(request, user=self.principal, token="valid-token")

        response = UserStatusView.as_view()(request, user_id=self.principal.id)

        self.assertEqual(response.status_code, 400)
        set_status.assert_not_called()
