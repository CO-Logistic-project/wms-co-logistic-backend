from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.usuarios.models import Permiso, Rol, RolPermiso, Usuario, UsuarioRol


PERMISSIONS = {
    "dashboard.ver": "Acceder al panel principal del WMS.",
    "usuarios.ver": "Consultar el módulo y listado de usuarios.",
    "usuarios.crear": "Registrar usuarios en el WMS con una contraseña inicial temporal.",
    "usuarios.editar": "Actualizar la información de los usuarios.",
    "usuarios.desactivar": "Desactivar y reactivar cuentas de usuario.",
    "usuarios.asignar_roles": "Asignar roles de acceso a los usuarios.",
    "roles.ver": "Consultar roles y permisos.",
    "roles.gestionar": "Crear y actualizar roles y sus permisos.",
    "productos.ver": "Consultar y filtrar el catálogo de productos.",
    "productos.crear": "Registrar productos en el catálogo maestro.",
    "productos.editar": "Actualizar productos sin reemplazar su identidad.",
    "clientes.ver": "Consultar el catálogo de clientes.",
    "clientes.crear": "Registrar clientes en el catálogo maestro.",
    "clientes.editar": "Actualizar clientes sin reemplazar su identidad.",
    "almacenes.ver": "Consultar almacenes del WMS.",
    "almacenes.crear": "Registrar almacenes del WMS.",
    "ubicaciones.ver": "Consultar zonas, ubicaciones y su ocupación.",
    "ubicaciones.crear": "Registrar zonas y ubicaciones.",
    "ubicaciones.editar": "Actualizar o desactivar ubicaciones sin stock.",
    "importaciones.ejecutar": "Importar catálogos maestros desde plantillas.",
    "recepciones.ver": "Consultar recepciones y su trazabilidad histórica.",
    "recepciones.crear": "Registrar ingresos desde guías de remisión.",
    "recepciones.validar": "Validar cantidades y registrar discrepancias.",
    "recepciones.asignar_ubicacion": "Asignar mercancía recibida a ubicaciones.",
    "recepciones.incidencias": "Registrar incidencias detectadas al ingreso.",
    "recepciones.lotes": "Registrar lotes y vencimientos de mercancía recibida.",
    "recepciones.imprimir": "Generar e imprimir pedidos de ingreso.",
    "inventario.ver": "Consultar existencias y ubicación actual del stock.",
    "inventario.ocupacion": "Consultar capacidad utilizada y disponible del almacén.",
    "inventario.vencimientos": "Consultar alertas de lotes próximos a vencer.",
    "movimientos.ver": "Consultar el historial de movimientos internos.",
    "movimientos.crear": "Registrar solicitudes de traslado interno.",
    "movimientos.confirmar": "Confirmar la ejecución física de traslados.",
    "movimientos.reempaque": "Dividir y reempacar pallets conservando su trazabilidad.",
    "pedidos.ver": "Consultar y monitorear pedidos de salida.",
    "pedidos.crear": "Generar pedidos desde guías de remisión de salida.",
    "pedidos.validar_stock": "Validar y reservar stock para pedidos de salida.",
    "pedidos.preparar": "Confirmar cantidades preparadas para despacho.",
    "pedidos.cancelar": "Cancelar pedidos y liberar sus reservas de stock.",
    "pedidos.imprimir": "Generar e imprimir el pedido de salida.",
    "despachos.ver": "Monitorear despachos pendientes y cerrados.",
    "despachos.cerrar": "Registrar la salida y descontar el inventario confirmado.",
    "despachos.incidencias": "Registrar incidencias detectadas durante la salida.",
    "reportes.ver": "Consultar indicadores, ocupación y análisis operativo.",
    "reportes.exportar": "Exportar reportes operativos en PDF y Excel.",
    "trazabilidad.ver": "Consultar la trazabilidad integral de los productos.",
    "planificacion.ver": "Consultar proyecciones, tendencias y alertas de capacidad.",
    "operaciones_tecnicas.ver": "Consultar monitoreo y operación técnica del ERP.",
    "operaciones_tecnicas.gestionar": "Gestionar respaldos, retención e integraciones técnicas.",
    "operaciones_tecnicas.restaurar": "Ejecutar restauraciones controladas de la base de datos.",
    "auditoria.ver": "Consultar eventos críticos de auditoría.",
    "auditoria.exportar": "Exportar eventos críticos de auditoría.",
    "despliegues.gestionar": "Registrar despliegues y ejecutar reversiones controladas.",
    "despliegues.aprobar": "Aprobar versiones candidatas para despliegue.",
    "acondicionamiento.ver": "Consultar solicitudes, ejecuciones y estados de facturación del acondicionamiento.",
    "acondicionamiento.solicitar": "Solicitar servicios facturables de repaletizado.",
    "acondicionamiento.ejecutar": "Registrar la ejecución de repaletizados y reencajados.",
    "acondicionamiento.facturacion": "Generar reportes y enviar servicios de acondicionamiento a facturación.",
}


class Command(BaseCommand):
    help = "Crea el acceso base y asigna Administrador TI a un usuario existente."

    def add_arguments(self, parser):
        parser.add_argument("--admin-email", required=True)

    def handle(self, *args, **options):
        email = options["admin_email"].strip().lower()
        try:
            user = Usuario.objects.get(correo__iexact=email)
        except Usuario.DoesNotExist as exc:
            raise CommandError(
                f"No existe un perfil WMS para {email}."
            ) from exc

        with transaction.atomic():
            permission_ids = []
            for name, description in PERMISSIONS.items():
                permission, _ = Permiso.objects.update_or_create(
                    nombre=name,
                    defaults={"descripcion": description, "estado": True},
                )
                permission_ids.append(permission.id_permiso)

            role, _ = Rol.objects.update_or_create(
                nombre="Administrador TI",
                defaults={
                    "descripcion": "Administración de usuarios, roles y accesos.",
                    "estado": True,
                },
            )
            RolPermiso.objects.filter(id_rol=role.id_rol).exclude(
                id_permiso__in=permission_ids
            ).delete()
            for permission_id in permission_ids:
                RolPermiso.objects.get_or_create(
                    id_rol=role.id_rol, id_permiso=permission_id
                )
            UsuarioRol.objects.get_or_create(
                id_usuario=user.id_usuario, id_rol=role.id_rol
            )

            operations_role, _ = Rol.objects.update_or_create(
                nombre="Jefe de Operaciones",
                defaults={
                    "descripcion": "Gestión de productos y clientes maestros.",
                    "estado": True,
                },
            )
            operations_permissions = Permiso.objects.filter(
                nombre__in=[
                    "productos.ver",
                    "productos.crear",
                    "productos.editar",
                    "clientes.ver",
                    "clientes.crear",
                    "clientes.editar",
                    "almacenes.ver",
                    "almacenes.crear",
                    "ubicaciones.ver",
                    "ubicaciones.crear",
                    "ubicaciones.editar",
                    "recepciones.ver",
                    "inventario.ver",
                    "inventario.ocupacion",
                    "inventario.vencimientos",
                    "movimientos.ver",
                    "movimientos.crear",
                    "pedidos.ver",
                    "pedidos.crear",
                    "pedidos.validar_stock",
                    "pedidos.cancelar",
                    "pedidos.imprimir",
                    "despachos.ver",
                    "reportes.ver",
                    "reportes.exportar",
                    "trazabilidad.ver",
                    "planificacion.ver",
                    "acondicionamiento.ver",
                    "acondicionamiento.solicitar",
                    "acondicionamiento.ejecutar",
                    "acondicionamiento.facturacion",
                ]
            )
            for permission in operations_permissions:
                RolPermiso.objects.get_or_create(
                    id_rol=operations_role.id_rol,
                    id_permiso=permission.id_permiso,
                )

            operator_role, _ = Rol.objects.update_or_create(
                nombre="Operario de almacén",
                defaults={
                    "descripcion": "Consulta operativa del catálogo de productos.",
                    "estado": True,
                },
            )
            location_view_permission = Permiso.objects.get(
                nombre="ubicaciones.ver"
            )
            operator_permissions = Permiso.objects.filter(
                nombre__in=[
                    "productos.ver",
                    "ubicaciones.ver",
                    "recepciones.ver",
                    "recepciones.crear",
                    "recepciones.validar",
                    "recepciones.asignar_ubicacion",
                    "recepciones.incidencias",
                    "recepciones.lotes",
                    "inventario.ver",
                    "inventario.vencimientos",
                    "movimientos.ver",
                    "movimientos.crear",
                    "movimientos.reempaque",
                    "pedidos.ver",
                    "pedidos.validar_stock",
                    "pedidos.preparar",
                    "despachos.ver",
                    "despachos.cerrar",
                    "despachos.incidencias",
                    "acondicionamiento.ver",
                    "acondicionamiento.ejecutar",
                ]
            )
            for permission in operator_permissions:
                RolPermiso.objects.get_or_create(
                    id_rol=operator_role.id_rol,
                    id_permiso=permission.id_permiso,
                )

            management_role, _ = Rol.objects.update_or_create(
                nombre="Gerencia",
                defaults={
                    "descripcion": "Consulta ejecutiva de clientes y catálogos.",
                    "estado": True,
                },
            )
            client_view_permission = Permiso.objects.get(nombre="clientes.ver")
            RolPermiso.objects.get_or_create(
                id_rol=management_role.id_rol,
                id_permiso=client_view_permission.id_permiso,
            )
            for permission in Permiso.objects.filter(
                nombre__in=["reportes.ver", "reportes.exportar", "trazabilidad.ver", "planificacion.ver"]
            ):
                RolPermiso.objects.get_or_create(
                    id_rol=management_role.id_rol,
                    id_permiso=permission.id_permiso,
                )

            inventory_role, _ = Rol.objects.update_or_create(
                nombre="Analista de Inventarios",
                defaults={
                    "descripcion": "Registro, validación y seguimiento de recepciones.",
                    "estado": True,
                },
            )
            for permission in Permiso.objects.filter(
                nombre__in=[
                    "productos.ver",
                    "clientes.ver",
                    "ubicaciones.ver",
                    "recepciones.ver",
                    "recepciones.crear",
                    "recepciones.validar",
                    "recepciones.asignar_ubicacion",
                    "recepciones.incidencias",
                    "recepciones.lotes",
                    "recepciones.imprimir",
                    "inventario.ver",
                    "inventario.ocupacion",
                    "inventario.vencimientos",
                    "movimientos.ver",
                    "movimientos.crear",
                    "movimientos.confirmar",
                    "movimientos.reempaque",
                    "pedidos.ver",
                    "pedidos.crear",
                    "pedidos.validar_stock",
                    "pedidos.preparar",
                    "pedidos.imprimir",
                    "despachos.ver",
                    "despachos.cerrar",
                    "despachos.incidencias",
                    "reportes.ver",
                    "reportes.exportar",
                    "trazabilidad.ver",
                    "planificacion.ver",
                    "acondicionamiento.ver",
                    "acondicionamiento.solicitar",
                    "acondicionamiento.ejecutar",
                    "acondicionamiento.facturacion",
                ]
            ):
                RolPermiso.objects.get_or_create(
                    id_rol=inventory_role.id_rol,
                    id_permiso=permission.id_permiso,
                )

            client_role, _ = Rol.objects.update_or_create(
                nombre="Cliente",
                defaults={
                    "descripcion": "Solicitud y consulta de servicios de acondicionamiento.",
                    "estado": True,
                },
            )
            for permission in Permiso.objects.filter(
                nombre__in=["acondicionamiento.ver", "acondicionamiento.solicitar"]
            ):
                RolPermiso.objects.get_or_create(
                    id_rol=client_role.id_rol,
                    id_permiso=permission.id_permiso,
                )

            forklift_role, _ = Rol.objects.update_or_create(
                nombre="Montacarguista",
                defaults={
                    "descripcion": "Consulta operativa de ubicaciones.",
                    "estado": True,
                },
            )
            RolPermiso.objects.get_or_create(
                id_rol=forklift_role.id_rol,
                id_permiso=location_view_permission.id_permiso,
            )
            for permission in Permiso.objects.filter(
                nombre__in=[
                    "recepciones.ver",
                    "recepciones.asignar_ubicacion",
                    "inventario.ver",
                    "movimientos.ver",
                    "movimientos.confirmar",
                    "pedidos.ver",
                    "pedidos.validar_stock",
                    "pedidos.preparar",
                    "despachos.ver",
                    "despachos.cerrar",
                    "despachos.incidencias",
                ]
            ):
                RolPermiso.objects.get_or_create(
                    id_rol=forklift_role.id_rol,
                    id_permiso=permission.id_permiso,
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"Acceso Administrador TI configurado para {user.correo}."
            )
        )
