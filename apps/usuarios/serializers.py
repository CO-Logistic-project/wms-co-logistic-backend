from types import SimpleNamespace

from rest_framework import serializers

from .local_auth import check_password_policy
from .models import Permiso, Rol, Usuario


def _strip(value):
    return value.strip()


class LoginSerializer(serializers.Serializer):
    correo = serializers.CharField(max_length=255, trim_whitespace=True)
    password = serializers.CharField(
        max_length=128, write_only=True, trim_whitespace=False
    )


class PasswordChangeSerializer(serializers.Serializer):
    password_actual = serializers.CharField(
        max_length=128, write_only=True, trim_whitespace=False
    )
    password_nueva = serializers.CharField(
        max_length=128, write_only=True, trim_whitespace=False
    )


class UserCreateSerializer(serializers.Serializer):
    nombre = serializers.CharField(max_length=255, trim_whitespace=True)
    apellido = serializers.CharField(max_length=255, trim_whitespace=True)
    correo = serializers.EmailField(max_length=255)
    password = serializers.CharField(
        min_length=8, max_length=128, write_only=True, trim_whitespace=False
    )
    role_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        allow_empty=True,
        default=list,
    )

    def validate_nombre(self, value):
        return _strip(value)

    def validate_apellido(self, value):
        return _strip(value)

    def validate_correo(self, value):
        normalized = value.strip().lower()
        if Usuario.objects.filter(correo__iexact=normalized).exists():
            raise serializers.ValidationError(
                "Ya existe un usuario con este correo."
            )
        return normalized

    def validate_role_ids(self, value):
        role_ids = sorted(set(value))
        if Rol.objects.filter(id_rol__in=role_ids, estado=True).count() != len(
            role_ids
        ):
            raise serializers.ValidationError(
                "Uno o más roles no existen o están inactivos."
            )
        return role_ids

    def validate(self, attrs):
        profile = SimpleNamespace(
            correo=attrs["correo"],
            nombre=attrs["nombre"],
            apellido=attrs["apellido"],
        )
        check_password_policy(attrs["password"], profile)
        return attrs


class UserUpdateSerializer(serializers.Serializer):
    nombre = serializers.CharField(max_length=255, trim_whitespace=True)
    apellido = serializers.CharField(max_length=255, trim_whitespace=True)
    correo = serializers.EmailField(max_length=255)

    def validate_nombre(self, value):
        return _strip(value)

    def validate_apellido(self, value):
        return _strip(value)

    def validate_correo(self, value):
        normalized = value.strip().lower()
        user_id = self.context["user_id"]
        if Usuario.objects.filter(correo__iexact=normalized).exclude(
            id_usuario=user_id
        ).exists():
            raise serializers.ValidationError(
                "Ya existe un usuario con este correo."
            )
        return normalized


class UserStatusSerializer(serializers.Serializer):
    estado = serializers.BooleanField()


class RoleAssignmentSerializer(serializers.Serializer):
    role_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1), allow_empty=True
    )

    def validate_role_ids(self, value):
        role_ids = sorted(set(value))
        if Rol.objects.filter(id_rol__in=role_ids, estado=True).count() != len(
            role_ids
        ):
            raise serializers.ValidationError(
                "Uno o más roles no existen o están inactivos."
            )
        return role_ids


class RoleWriteSerializer(serializers.Serializer):
    nombre = serializers.CharField(max_length=255, trim_whitespace=True)
    descripcion = serializers.CharField(
        max_length=1000, trim_whitespace=True, allow_blank=True, default=""
    )
    estado = serializers.BooleanField(default=True)
    permission_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1), allow_empty=True, default=list
    )

    def validate_nombre(self, value):
        normalized = value.strip()
        query = Rol.objects.filter(nombre__iexact=normalized)
        role_id = self.context.get("role_id")
        if role_id is not None:
            query = query.exclude(id_rol=role_id)
        if query.exists():
            raise serializers.ValidationError("Ya existe un rol con este nombre.")
        return normalized

    def validate_permission_ids(self, value):
        permission_ids = sorted(set(value))
        if Permiso.objects.filter(
            id_permiso__in=permission_ids, estado=True
        ).count() != len(permission_ids):
            raise serializers.ValidationError(
                "Uno o más permisos no existen o están inactivos."
            )
        return permission_ids
