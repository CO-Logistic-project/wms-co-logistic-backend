import uuid

from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .local_auth import (
    generate_temporary_password,
    revoke_all_sessions,
    set_password,
)
from .models import Permiso, Rol, RolPermiso, Usuario, UsuarioRol


def get_user_roles(user_id):
    role_ids = UsuarioRol.objects.filter(id_usuario=user_id).values_list(
        "id_rol", flat=True
    )
    return list(
        Rol.objects.filter(id_rol__in=role_ids)
        .order_by("nombre")
        .values("id_rol", "nombre", "estado")
    )


def serialize_user(user):
    return {
        "id_usuario": str(user.id_usuario),
        "nombre": user.nombre,
        "apellido": user.apellido,
        "correo": user.correo,
        "estado": user.estado,
        "fecha_registro": user.fecha_registro,
        "fecha_actualizacion": user.fecha_actualizacion,
        "roles": get_user_roles(user.id_usuario),
    }


def serialize_role(role):
    permission_ids = RolPermiso.objects.filter(id_rol=role.id_rol).values_list(
        "id_permiso", flat=True
    )
    permissions = list(
        Permiso.objects.filter(id_permiso__in=permission_ids)
        .order_by("nombre")
        .values("id_permiso", "nombre", "descripcion", "estado")
    )
    return {
        "id_rol": role.id_rol,
        "nombre": role.nombre,
        "descripcion": role.descripcion or "",
        "estado": role.estado,
        "permisos": permissions,
    }


def build_user_access(principal):
    """Build the effective roles and permissions for an authenticated user."""
    roles = [role for role in get_user_roles(principal.id) if role["estado"]]
    active_role_ids = [role["id_rol"] for role in roles]
    permission_ids = RolPermiso.objects.filter(
        id_rol__in=active_role_ids
    ).values_list("id_permiso", flat=True)
    permissions = list(
        Permiso.objects.filter(id_permiso__in=permission_ids, estado=True)
        .order_by("nombre")
        .values_list("nombre", flat=True)
        .distinct()
    )

    profile = principal.profile
    return {
        "id": principal.id,
        "debe_cambiar_password": principal.must_change_password,
        "correo": profile.correo,
        "nombre": profile.nombre,
        "apellido": profile.apellido,
        "roles": [
            {"id_rol": role["id_rol"], "nombre": role["nombre"]}
            for role in roles
        ],
        "permisos": permissions,
    }


def create_application_user(validated_data):
    """Create profile, roles and the initial (must-change) credential."""
    now = timezone.now()
    try:
        with transaction.atomic():
            user = Usuario.objects.create(
                id_usuario=uuid.uuid4(),
                nombre=validated_data["nombre"],
                apellido=validated_data["apellido"],
                correo=validated_data["correo"],
                estado=True,
                fecha_registro=now,
                fecha_actualizacion=now,
            )
            UsuarioRol.objects.bulk_create(
                [
                    UsuarioRol(id_usuario=user.id_usuario, id_rol=role_id)
                    for role_id in validated_data["role_ids"]
                ]
            )
            set_password(
                user.id_usuario,
                validated_data["password"],
                must_change=True,
                user=user,
            )
    except IntegrityError as exc:
        raise ValidationError(
            {"correo": ["No fue posible registrar el usuario sin duplicarlo."]}
        ) from exc

    return user


def update_application_user(user, validated_data):
    try:
        with transaction.atomic():
            user.nombre = validated_data["nombre"]
            user.apellido = validated_data["apellido"]
            user.correo = validated_data["correo"]
            user.fecha_actualizacion = timezone.now()
            user.save(
                update_fields=[
                    "nombre",
                    "apellido",
                    "correo",
                    "fecha_actualizacion",
                ]
            )
    except IntegrityError as exc:
        raise ValidationError(
            {"correo": ["No fue posible actualizar el usuario sin duplicarlo."]}
        ) from exc

    return user


def replace_user_roles(user, role_ids):
    with transaction.atomic():
        UsuarioRol.objects.filter(id_usuario=user.id_usuario).delete()
        UsuarioRol.objects.bulk_create(
            [
                UsuarioRol(id_usuario=user.id_usuario, id_rol=role_id)
                for role_id in role_ids
            ]
        )
    return user


def set_application_user_status(user, active):
    if user.estado == active:
        return user

    with transaction.atomic():
        user.estado = active
        user.fecha_actualizacion = timezone.now()
        user.save(update_fields=["estado", "fecha_actualizacion"])
        if not active:
            revoke_all_sessions(user.id_usuario)

    return user


def reset_user_password(user):
    """Set a one-time temporary password and return it (shown only once)."""
    temporary = generate_temporary_password(user)
    set_password(user.id_usuario, temporary, must_change=True, user=user)
    return temporary


def save_role(validated_data, role=None):
    with transaction.atomic():
        if role is None:
            role = Rol.objects.create(
                nombre=validated_data["nombre"],
                descripcion=validated_data["descripcion"],
                estado=validated_data["estado"],
            )
        else:
            role.nombre = validated_data["nombre"]
            role.descripcion = validated_data["descripcion"]
            role.estado = validated_data["estado"]
            role.save(update_fields=["nombre", "descripcion", "estado"])

        RolPermiso.objects.filter(id_rol=role.id_rol).delete()
        RolPermiso.objects.bulk_create(
            [
                RolPermiso(id_rol=role.id_rol, id_permiso=permission_id)
                for permission_id in validated_data["permission_ids"]
            ]
        )
    return role
