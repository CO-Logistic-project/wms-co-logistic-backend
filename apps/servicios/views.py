from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.usuarios.permissions import require_application_permission, user_has_permission
from apps.inventario.models import Stock
from apps.inventario.services import serialize_stocks
from apps.maestros.models import Cliente, Pallet
from apps.reportes.exports import build_pdf, build_xlsx

from .models import (
    Despliegue,
    EjecucionIntegracion,
    EventoAuditoria,
    IncidenteSistema,
    PoliticaConservacion,
    RespaldoBaseDatos,
    RestauracionBaseDatos,
    Reencajado,
    Repaletizado,
    Servicio,
    VersionDespliegue,
)
from .conditioning import billing_rows, serialize_services
from .serializers import (
    ReboxingSerializer,
    RepalletExecutionSerializer,
    RepalletRequestSerializer,
)
from .technical import (
    audit_csv,
    create_backup,
    get_schedule,
    performance_summary,
    principal_data,
    restore_backup,
    serialize_audit,
    serialize_backup,
    system_health,
    validate_backup,
)


def _positive_integer(value, field, minimum=1, maximum=36500):
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError({field: ["Debe ser un número entero."]}) from exc
    if not minimum <= parsed <= maximum:
        raise ValidationError({field: [f"Debe estar entre {minimum} y {maximum}."]})
    return parsed


def _date(value, field):
    if not value:
        return None
    try:
        return timezone.datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValidationError({field: ["Usa el formato AAAA-MM-DD."]}) from exc


def _schedule_data(item):
    return {
        "id_programacion": item.id_programacion,
        "activa": item.activa,
        "frecuencia_horas": item.frecuencia_horas,
        "retencion_dias": item.retencion_dias,
        "proxima_ejecucion": item.proxima_ejecucion,
        "ultima_ejecucion": item.ultima_ejecucion,
        "fecha_actualizacion": item.fecha_actualizacion,
    }


def _policy_data(item):
    return {
        "id_politica": item.id_politica,
        "categoria": item.categoria,
        "periodo_dias": item.periodo_dias,
        "eliminacion_habilitada": item.eliminacion_habilitada,
        "protege_operaciones": item.protege_operaciones,
        "descripcion": item.descripcion,
        "fecha_actualizacion": item.fecha_actualizacion,
    }


def _integration_data(item):
    return {
        "id_ejecucion": item.id_ejecucion,
        "integracion": item.integracion,
        "operacion": item.operacion,
        "estado": item.estado,
        "fecha_inicio": item.fecha_inicio,
        "fecha_fin": item.fecha_fin,
        "datos_procesados": item.datos_procesados,
        "detalle_error": item.detalle_error,
        "reintento_de": item.reintento_de,
        "intentos": item.intentos,
    }


def _version_data(item):
    return {
        "id_version": item.id_version,
        "version": item.version,
        "descripcion": item.descripcion,
        "plan_reversion": item.plan_reversion,
        "aprobada": item.aprobada,
        "fecha_registro": item.fecha_registro,
        "fecha_aprobacion": item.fecha_aprobacion,
    }


def _deployment_data(item):
    version = VersionDespliegue.objects.filter(id_version=item.id_version).first()
    return {
        "id_despliegue": item.id_despliegue,
        "id_version": item.id_version,
        "version": version.version if version else str(item.id_version),
        "ambiente": item.ambiente,
        "estado": item.estado,
        "id_respaldo_previo": item.id_respaldo_previo,
        "version_anterior": item.version_anterior,
        "fecha_inicio": item.fecha_inicio,
        "fecha_fin": item.fecha_fin,
        "usuario": item.usuario,
        "resultado": item.resultado,
    }


def _ensure_policies():
    defaults = [
        ("AUDITORIA", 730, True, "Conserva trazas críticas y evita eliminar eventos ligados a operaciones."),
        ("OPERACIONES", 1825, True, "Protege recepciones, inventario, movimientos y despachos históricos."),
        ("RESPALDOS", 90, False, "Retención del catálogo de respaldos técnicos."),
        ("METRICAS", 180, False, "Retención de telemetría y tiempos de respuesta."),
    ]
    for category, days, protected, description in defaults:
        PoliticaConservacion.objects.get_or_create(
            categoria=category,
            defaults={
                "periodo_dias": days,
                "eliminacion_habilitada": not protected,
                "protege_operaciones": protected,
                "descripcion": description,
                "fecha_actualizacion": timezone.now(),
            },
        )


class TechnicalOverviewView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        health = system_health(record_incidents=True)
        _ensure_policies()
        latest_backup = RespaldoBaseDatos.objects.order_by("-fecha_inicio").first()
        latest_deployment = Despliegue.objects.order_by("-fecha_inicio").first()
        return Response({
            "salud": health,
            "fallos_registrados": [
                {
                    "id_incidente": item.id_incidente,
                    "componente": item.componente,
                    "estado": item.estado,
                    "fecha_inicio": item.fecha_inicio,
                    "fecha_fin": item.fecha_fin,
                    "duracion_segundos": round(((item.fecha_fin or timezone.now()) - item.fecha_inicio).total_seconds()),
                    "detalle": item.detalle,
                }
                for item in IncidenteSistema.objects.order_by("-fecha_inicio")[:20]
            ],
            "ultimo_respaldo": serialize_backup(latest_backup) if latest_backup else None,
            "ultimo_despliegue": _deployment_data(latest_deployment) if latest_deployment else None,
            "conteos": {
                "respaldos_validos": RespaldoBaseDatos.objects.filter(valido=True).count(),
                "integraciones_fallidas": EjecucionIntegracion.objects.filter(estado="FALLIDO").count(),
                "eventos_auditoria": EventoAuditoria.objects.count(),
                "incidentes_abiertos": IncidenteSistema.objects.filter(estado="ABIERTO").count(),
            },
        })


class HealthCheckView(APIView):
    def post(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.gestionar")
        return Response(system_health(record_incidents=True))


class BackupListCreateView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        return Response({
            "respaldos": [serialize_backup(item) for item in RespaldoBaseDatos.objects.order_by("-fecha_inicio")[:100]],
            "restauraciones": [
                {
                    "id_restauracion": item.id_restauracion,
                    "id_respaldo": item.id_respaldo,
                    "estado": item.estado,
                    "fecha_inicio": item.fecha_inicio,
                    "fecha_fin": item.fecha_fin,
                    "usuario": item.usuario,
                    "resultado": item.resultado,
                }
                for item in RestauracionBaseDatos.objects.order_by("-fecha_inicio")[:50]
            ],
            "restauracion_habilitada": settings.TECHNICAL_ALLOW_RESTORE,
        })

    def post(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.gestionar")
        backup = create_backup(request.user, "MANUAL")
        response_status = status.HTTP_201_CREATED if backup.valido else status.HTTP_422_UNPROCESSABLE_ENTITY
        return Response(serialize_backup(backup), status=response_status)


class BackupValidateView(APIView):
    def post(self, request, backup_id):
        require_application_permission(request.user, "operaciones_tecnicas.gestionar")
        backup = get_object_or_404(RespaldoBaseDatos, id_respaldo=backup_id)
        return Response(serialize_backup(validate_backup(backup)))


class BackupRestoreView(APIView):
    def post(self, request, backup_id):
        require_application_permission(request.user, "operaciones_tecnicas.restaurar")
        backup = get_object_or_404(RespaldoBaseDatos, id_respaldo=backup_id)
        restoration = restore_backup(backup, request.user, request.data.get("confirmacion", ""))
        return Response({
            "id_restauracion": restoration.id_restauracion,
            "estado": restoration.estado,
            "resultado": restoration.resultado,
            "fecha_inicio": restoration.fecha_inicio,
            "fecha_fin": restoration.fecha_fin,
        }, status=status.HTTP_201_CREATED)


class BackupScheduleView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        return Response(_schedule_data(get_schedule()))

    def patch(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.gestionar")
        schedule = get_schedule()
        active = bool(request.data.get("activa", schedule.activa))
        frequency = _positive_integer(request.data.get("frecuencia_horas", schedule.frecuencia_horas), "frecuencia_horas", 1, 8760)
        retention = _positive_integer(request.data.get("retencion_dias", schedule.retencion_dias), "retencion_dias", 1, 3650)
        now = timezone.now()
        schedule.activa = active
        schedule.frecuencia_horas = frequency
        schedule.retencion_dias = retention
        schedule.proxima_ejecucion = now + timedelta(hours=frequency) if active else None
        schedule.id_usuario_actualiza = request.user.id
        schedule.fecha_actualizacion = now
        schedule.save()
        return Response(_schedule_data(schedule))


def _audit_query(request):
    query = EventoAuditoria.objects.all().order_by("-fecha")
    search = request.query_params.get("buscar", "").strip()
    if search:
        query = query.filter(Q(usuario__icontains=search) | Q(ruta__icontains=search) | Q(modulo__icontains=search))
    for field in ("modulo", "accion", "resultado"):
        value = request.query_params.get(field, "").strip()
        if value:
            query = query.filter(**{f"{field}__iexact": value})
    date_from = _date(request.query_params.get("fecha_desde", ""), "fecha_desde")
    date_to = _date(request.query_params.get("fecha_hasta", ""), "fecha_hasta")
    if date_from:
        query = query.filter(fecha__date__gte=date_from)
    if date_to:
        query = query.filter(fecha__date__lte=date_to)
    if date_from and date_to and date_from > date_to:
        raise ValidationError({"fecha_hasta": ["La fecha final debe ser posterior a la inicial."]})
    return query


class AuditEventListView(APIView):
    def get(self, request):
        require_application_permission(request.user, "auditoria.ver")
        return Response([serialize_audit(item) for item in _audit_query(request)[:500]])


class AuditExportView(APIView):
    def get(self, request):
        require_application_permission(request.user, "auditoria.exportar")
        content = audit_csv(_audit_query(request)[:5000])
        response = HttpResponse(content, content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = 'attachment; filename="auditoria-wms.csv"'
        return response


class RetentionPolicyView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        _ensure_policies()
        return Response([_policy_data(item) for item in PoliticaConservacion.objects.order_by("categoria")])

    def post(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.gestionar")
        category = request.data.get("categoria", "").strip().upper()
        if not category:
            raise ValidationError({"categoria": ["Este campo es obligatorio."]})
        days = _positive_integer(request.data.get("periodo_dias"), "periodo_dias")
        protected = bool(request.data.get("protege_operaciones", True))
        delete_enabled = bool(request.data.get("eliminacion_habilitada", False))
        if protected and delete_enabled:
            raise ValidationError({"eliminacion_habilitada": ["No se puede habilitar eliminación para información operativa protegida."]})
        user_id, _ = principal_data(request.user)
        policy, created = PoliticaConservacion.objects.update_or_create(
            categoria=category,
            defaults={
                "periodo_dias": days,
                "eliminacion_habilitada": delete_enabled,
                "protege_operaciones": protected,
                "descripcion": request.data.get("descripcion", "").strip(),
                "id_usuario_actualiza": user_id,
                "fecha_actualizacion": timezone.now(),
            },
        )
        return Response(_policy_data(policy), status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class IntegrationExecutionView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        return Response([_integration_data(item) for item in EjecucionIntegracion.objects.order_by("-fecha_inicio")[:200]])

    def post(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.gestionar")
        integration = request.data.get("integracion", "").strip()
        operation = request.data.get("operacion", "").strip()
        state = request.data.get("estado", "").strip().upper()
        if not integration or not operation or state not in {"COMPLETADO", "FALLIDO", "PROCESANDO"}:
            raise ValidationError({"integracion": ["Indica integración, operación y un estado válido."]})
        user_id, _ = principal_data(request.user)
        item = EjecucionIntegracion.objects.create(
            integracion=integration,
            operacion=operation,
            estado=state,
            fecha_inicio=timezone.now(),
            fecha_fin=None if state == "PROCESANDO" else timezone.now(),
            datos_procesados=max(0, int(request.data.get("datos_procesados", 0))),
            detalle_error=request.data.get("detalle_error", "").strip(),
            intentos=1,
            id_usuario=user_id,
        )
        return Response(_integration_data(item), status=status.HTTP_201_CREATED)


class IntegrationRetryView(APIView):
    def post(self, request, execution_id):
        require_application_permission(request.user, "operaciones_tecnicas.gestionar")
        original = get_object_or_404(EjecucionIntegracion, id_ejecucion=execution_id)
        if original.estado != "FALLIDO":
            raise ValidationError({"estado": ["Solo se pueden reintentar integraciones fallidas."]})
        user_id, _ = principal_data(request.user)
        started = timezone.now()
        try:
            if "base" in original.integracion.lower() or "database" in original.integracion.lower():
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            else:
                raise RuntimeError("Esta integración no tiene un reintento automático autorizado.")
            state, detail = "COMPLETADO", "Reintento técnico completado."
        except Exception as exc:
            state, detail = "FALLIDO", str(exc)
        retried = EjecucionIntegracion.objects.create(
            integracion=original.integracion,
            operacion=original.operacion,
            estado=state,
            fecha_inicio=started,
            fecha_fin=timezone.now(),
            datos_procesados=original.datos_procesados if state == "COMPLETADO" else 0,
            detalle_error=detail,
            reintento_de=original.id_ejecucion,
            intentos=original.intentos + 1,
            id_usuario=user_id,
        )
        return Response(_integration_data(retried), status=status.HTTP_201_CREATED)


class PerformanceView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        days = _positive_integer(request.query_params.get("dias", 7), "dias", 1, 365)
        return Response(performance_summary(days))


class ReleaseVersionView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        return Response([_version_data(item) for item in VersionDespliegue.objects.order_by("-fecha_registro")[:100]])

    def post(self, request):
        require_application_permission(request.user, "despliegues.gestionar")
        version = request.data.get("version", "").strip()
        rollback = request.data.get("plan_reversion", "").strip()
        if not version or not rollback:
            raise ValidationError({"version": ["La versión y el plan de reversión son obligatorios."]})
        if VersionDespliegue.objects.filter(version__iexact=version).exists():
            raise ValidationError({"version": ["La versión ya está registrada."]})
        user_id, _ = principal_data(request.user)
        item = VersionDespliegue.objects.create(
            version=version,
            descripcion=request.data.get("descripcion", "").strip(),
            plan_reversion=rollback,
            aprobada=False,
            id_usuario_registro=user_id,
            fecha_registro=timezone.now(),
        )
        return Response(_version_data(item), status=status.HTTP_201_CREATED)


class ReleaseApproveView(APIView):
    def post(self, request, version_id):
        require_application_permission(request.user, "despliegues.aprobar")
        item = get_object_or_404(VersionDespliegue, id_version=version_id)
        user_id, _ = principal_data(request.user)
        item.aprobada = True
        item.id_usuario_aprueba = user_id
        item.fecha_aprobacion = timezone.now()
        item.save(update_fields=["aprobada", "id_usuario_aprueba", "fecha_aprobacion"])
        return Response(_version_data(item))


class DeploymentView(APIView):
    def get(self, request):
        require_application_permission(request.user, "operaciones_tecnicas.ver")
        return Response([_deployment_data(item) for item in Despliegue.objects.order_by("-fecha_inicio")[:100]])

    def post(self, request):
        require_application_permission(request.user, "despliegues.gestionar")
        version = get_object_or_404(VersionDespliegue, id_version=request.data.get("id_version"))
        if not version.aprobada:
            raise ValidationError({"version": ["Solo se puede desplegar una versión aprobada."]})
        environment = request.data.get("ambiente", "PRODUCCION").strip().upper()
        confirmation = request.data.get("confirmacion", "")
        expected = f"DESPLEGAR {version.version}"
        if confirmation != expected:
            raise ValidationError({"confirmacion": [f'Escribe exactamente "{expected}".']})
        latest = Despliegue.objects.filter(estado="COMPLETADO", ambiente=environment).order_by("-fecha_fin").first()
        backup = create_backup(request.user, "PRE_DESPLIEGUE")
        if not backup.valido:
            raise ValidationError({"respaldo": [f"No se desplegó porque el respaldo previo falló: {backup.resultado}"]})
        user_id, email = principal_data(request.user)
        with transaction.atomic():
            deployment = Despliegue.objects.create(
                id_version=version.id_version,
                ambiente=environment,
                estado="COMPLETADO",
                id_respaldo_previo=backup.id_respaldo,
                version_anterior=_deployment_data(latest)["version"] if latest else "",
                fecha_inicio=backup.fecha_inicio,
                fecha_fin=timezone.now(),
                id_usuario=user_id,
                usuario=email,
                resultado="Versión aprobada activada en el registro de producción con respaldo previo verificado.",
            )
        return Response(_deployment_data(deployment), status=status.HTTP_201_CREATED)


class DeploymentRollbackView(APIView):
    def post(self, request, deployment_id):
        require_application_permission(request.user, "despliegues.gestionar")
        deployment = get_object_or_404(Despliegue, id_despliegue=deployment_id)
        if deployment.estado != "COMPLETADO":
            raise ValidationError({"estado": ["Solo se puede revertir un despliegue completado."]})
        confirmation = request.data.get("confirmacion", "")
        expected = f"REVERTIR {deployment.id_despliegue}"
        if confirmation != expected:
            raise ValidationError({"confirmacion": [f'Escribe exactamente "{expected}".']})
        deployment.estado = "REVERTIDO"
        deployment.fecha_fin = timezone.now()
        deployment.resultado = f"Reversión controlada registrada. Versión objetivo: {deployment.version_anterior or 'sin versión previa'}; respaldo {deployment.id_respaldo_previo}."
        deployment.save(update_fields=["estado", "fecha_fin", "resultado"])
        return Response(_deployment_data(deployment))


# =====================================================
# EP-09 · ACONDICIONAMIENTO DE MERCADERÍA
# =====================================================


def _conditioning_queryset(request):
    queryset = Servicio.objects.filter(
        tipo_servicio__in=["REPALETIZADO", "REENCAJADO"]
    ).order_by("-fecha_servicio", "-id_servicio")
    service_type = request.query_params.get("tipo", "").strip().upper()
    service_status = request.query_params.get("estado", "").strip().upper()
    billing_status = request.query_params.get("estado_facturacion", "").strip().upper()
    client_id = request.query_params.get("id_cliente")
    search = request.query_params.get("q", "").strip()
    if service_type:
        queryset = queryset.filter(tipo_servicio=service_type)
    if service_status:
        queryset = queryset.filter(estado=service_status)
    if billing_status:
        queryset = queryset.filter(estado_facturacion=billing_status)
    if client_id:
        queryset = queryset.filter(id_cliente=_positive_integer(client_id, "id_cliente", maximum=2147483647))
    if search:
        queryset = queryset.filter(
            Q(codigo__icontains=search) | Q(descripcion__icontains=search)
        )
    return queryset


def _conditioning_file(title, services, file_format):
    headers, rows = billing_rows(services)
    if file_format == "xlsx":
        response = HttpResponse(
            build_xlsx(title, headers, rows),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        extension = "xlsx"
    elif file_format == "pdf":
        response = HttpResponse(
            build_pdf(title, headers, rows), content_type="application/pdf"
        )
        extension = "pdf"
    else:
        raise ValidationError({"formato": ["Los formatos permitidos son pdf y xlsx."]})
    response["Content-Disposition"] = f'attachment; filename="{title.lower().replace(" ", "-")}.{extension}"'
    return response


class ConditioningOptionsView(APIView):
    def get(self, request):
        if not (
            user_has_permission(request.user, "acondicionamiento.ver")
            or user_has_permission(request.user, "acondicionamiento.solicitar")
        ):
            require_application_permission(request.user, "acondicionamiento.ver")
        stocks = serialize_stocks(Stock.objects.order_by("id_stock"))
        return Response({
            "clientes": [
                {
                    "id_cliente": item.id_cliente,
                    "razon_social": item.razon_social,
                    "ruc": item.ruc,
                }
                for item in Cliente.objects.filter(estado=True).order_by("razon_social")
            ],
            "stocks": [item for item in stocks if item["cantidad_disponible"] > 0],
        })


class ConditioningServiceListView(APIView):
    def get(self, request):
        require_application_permission(request.user, "acondicionamiento.ver")
        return Response(serialize_services(_conditioning_queryset(request)[:500]))


class RepalletRequestView(APIView):
    def post(self, request):
        require_application_permission(request.user, "acondicionamiento.solicitar")
        serializer = RepalletRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        stock = data.pop("stock")
        user_id, _ = principal_data(request.user)
        now = timezone.now()
        with transaction.atomic():
            service = Servicio.objects.create(
                id_cliente=data["id_cliente"],
                codigo=data["codigo"],
                tipo_servicio="REPALETIZADO",
                estado="SOLICITADO",
                descripcion=data["descripcion"],
                cantidad=data["cantidad"],
                facturable=True,
                estado_facturacion="PENDIENTE",
                tarifa_aplicada=0,
                id_usuario_registro=user_id,
                fecha_servicio=now,
                observaciones=data["observaciones"],
            )
            Repaletizado.objects.create(
                id_servicio=service.id_servicio,
                id_stock=stock.id_stock,
                id_pallet_origen=stock.id_pallet,
                id_pallet_destino=None,
                cantidad_pallets=1,
                cliente_provee_pallet_destino=data["cliente_provee_pallet_destino"],
                tipo_pallet_destino=data["tipo_pallet_destino"],
                certificacion_destino=data["certificacion_destino"],
                codigo_pallet_destino="",
            )
        return Response(serialize_services([service])[0], status=status.HTTP_201_CREATED)


class RepalletExecutionView(APIView):
    def post(self, request, service_id):
        require_application_permission(request.user, "acondicionamiento.ejecutar")
        service = get_object_or_404(Servicio, id_servicio=service_id)
        if service.tipo_servicio != "REPALETIZADO":
            raise ValidationError({"tipo": ["El servicio no corresponde a un repaletizado."]})
        if service.estado not in {"SOLICITADO", "EN_PROCESO"}:
            raise ValidationError({"estado": ["El repaletizado ya fue ejecutado."]})
        detail = get_object_or_404(Repaletizado, id_servicio=service.id_servicio)
        stock = get_object_or_404(Stock, id_stock=detail.id_stock)
        serializer = RepalletExecutionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        available = stock.cantidad_total - stock.cantidad_reservada
        if data["cantidad"] > service.cantidad or data["cantidad"] > available:
            raise ValidationError({
                "cantidad": [f"La cantidad no puede superar lo solicitado ni el disponible ({available})."]
            })
        user_id, _ = principal_data(request.user)
        now = timezone.now()
        with transaction.atomic():
            if Pallet.objects.filter(
                codigo_barras__iexact=data["codigo_pallet_destino"]
            ).exists():
                raise ValidationError({
                    "codigo_pallet_destino": ["El código de pallet ya está registrado."]
                })
            pallet = Pallet.objects.create(
                codigo_barras=data["codigo_pallet_destino"],
                tipo=data["tipo_pallet_destino"],
                capacidad_referencial=None,
                id_pallet_padre=stock.id_pallet,
                estado="En uso",
                fecha_registro=now,
                fecha_actualizacion=now,
            )
            detail.id_pallet_destino = pallet.id_pallet
            detail.codigo_pallet_destino = pallet.codigo_barras
            detail.cantidad_pallets = data["numero_paletas"]
            detail.tipo_pallet_destino = data["tipo_pallet_destino"]
            detail.certificacion_destino = data["certificacion_destino"]
            detail.save(update_fields=[
                "id_pallet_destino", "codigo_pallet_destino", "cantidad_pallets",
                "tipo_pallet_destino", "certificacion_destino",
            ])
            service.estado = "COMPLETADO"
            service.descripcion = data["descripcion"]
            service.cantidad = data["cantidad"]
            service.tarifa_aplicada = data["tarifa"]
            service.estado_facturacion = "PENDIENTE"
            service.id_usuario_ejecucion = user_id
            service.fecha_ejecucion = now
            service.observaciones = data["observaciones"]
            service.save(update_fields=[
                "estado", "descripcion", "cantidad", "tarifa_aplicada",
                "estado_facturacion", "id_usuario_ejecucion", "fecha_ejecucion",
                "observaciones",
            ])
        return Response(serialize_services([service])[0])


class ReboxingView(APIView):
    def post(self, request):
        require_application_permission(request.user, "acondicionamiento.ejecutar")
        serializer = ReboxingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        stock = data.pop("stock")
        user_id, _ = principal_data(request.user)
        now = timezone.now()
        with transaction.atomic():
            service = Servicio.objects.create(
                id_cliente=data["id_cliente"],
                codigo=data["codigo"],
                tipo_servicio="REENCAJADO",
                estado="COMPLETADO",
                descripcion=data["descripcion"],
                cantidad=data["cantidad"],
                facturable=True,
                estado_facturacion="PENDIENTE",
                tarifa_aplicada=data["tarifa"],
                id_usuario_registro=user_id,
                id_usuario_ejecucion=user_id,
                fecha_servicio=now,
                fecha_ejecucion=now,
                observaciones=data["observaciones"],
            )
            Reencajado.objects.create(
                id_servicio=service.id_servicio,
                id_stock=stock.id_stock,
                cantidad_cajas_origen=data["cantidad_cajas_origen"],
                cantidad_cajas_destino=data["cantidad_cajas_destino"],
            )
        return Response(serialize_services([service])[0], status=status.HTTP_201_CREATED)


class ConditioningServiceReportView(APIView):
    def get(self, request, service_id):
        require_application_permission(request.user, "acondicionamiento.facturacion")
        file_format = request.query_params.get("formato", "pdf").lower()
        if file_format not in {"pdf", "xlsx"}:
            raise ValidationError({"formato": ["Los formatos permitidos son pdf y xlsx."]})
        service = get_object_or_404(Servicio, id_servicio=service_id, facturable=True)
        if service.estado != "COMPLETADO":
            raise ValidationError({"estado": ["Solo se reportan servicios completados."]})
        service.fecha_reporte = timezone.now()
        if service.estado_facturacion == "PENDIENTE":
            service.estado_facturacion = "GENERADO"
        service.save(update_fields=["fecha_reporte", "estado_facturacion"])
        return _conditioning_file(
            f"Servicio {service.codigo}", [service], file_format
        )


class ConditioningBillingReportView(APIView):
    def get(self, request):
        require_application_permission(request.user, "acondicionamiento.facturacion")
        services = list(_conditioning_queryset(request).filter(facturable=True, estado="COMPLETADO")[:1000])
        return _conditioning_file(
            "Reporte de acondicionamiento", services,
            request.query_params.get("formato", "xlsx").lower(),
        )


class ConditioningSendBillingView(APIView):
    def post(self, request, service_id):
        require_application_permission(request.user, "acondicionamiento.facturacion")
        service = get_object_or_404(Servicio, id_servicio=service_id, facturable=True)
        if service.estado != "COMPLETADO":
            raise ValidationError({"estado": ["Solo se envían servicios completados."]})
        if service.estado_facturacion == "ENVIADO":
            raise ValidationError({"estado_facturacion": ["El servicio ya fue enviado a facturación."]})
        service.estado_facturacion = "ENVIADO"
        service.fecha_reporte = service.fecha_reporte or timezone.now()
        service.save(update_fields=["estado_facturacion", "fecha_reporte"])
        return Response(serialize_services([service])[0])
