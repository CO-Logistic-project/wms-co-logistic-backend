from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from .technical import sanitize_payload
from .serializers import ReboxingSerializer, RepalletRequestSerializer
from .views import (
    BackupRestoreView,
    ConditioningSendBillingView,
    DeploymentView,
    HealthCheckView,
    RepalletExecutionView,
    RetentionPolicyView,
    _conditioning_file,
)


class TechnicalSecurityTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = SimpleNamespace(
            id="00000000-0000-0000-0000-000000000001",
            email="admin@cologistic.com",
            is_authenticated=True,
        )

    def request(self, method, path, data=None):
        request = getattr(self.factory, method)(path, data or {}, format="json")
        force_authenticate(request, user=self.user)
        return request

    def test_sensitive_audit_values_are_redacted_recursively(self):
        payload = sanitize_payload({"correo": "admin@test.com", "password": "secret", "nested": {"token": "jwt"}})
        self.assertEqual(payload["correo"], "admin@test.com")
        self.assertEqual(payload["password"], "[PROTEGIDO]")
        self.assertEqual(payload["nested"]["token"], "[PROTEGIDO]")

    @patch("apps.servicios.views.require_application_permission")
    @patch("apps.servicios.views.system_health")
    def test_health_check_requires_management_permission(self, health, permission):
        health.return_value = {"estado": "OPERATIVO", "disponibilidad": 100}
        response = HealthCheckView.as_view()(self.request("post", "/api/technical/health/check/"))
        self.assertEqual(response.status_code, 200)
        permission.assert_called_once_with(self.user, "operaciones_tecnicas.gestionar")

    @patch("apps.servicios.views.require_application_permission")
    @patch("apps.servicios.views.restore_backup")
    @patch("apps.servicios.views.get_object_or_404")
    def test_restore_passes_explicit_confirmation_to_controlled_service(self, get_object, restore, _):
        get_object.return_value = SimpleNamespace(id_respaldo=7)
        restore.return_value = SimpleNamespace(
            id_restauracion=3, estado="COMPLETADA", resultado="OK",
            fecha_inicio=None, fecha_fin=None,
        )
        response = BackupRestoreView.as_view()(self.request(
            "post", "/api/technical/backups/7/restore/", {"confirmacion": "RESTAURAR 7"}
        ), backup_id=7)
        self.assertEqual(response.status_code, 201)
        restore.assert_called_once_with(get_object.return_value, self.user, "RESTAURAR 7")

    @patch("apps.servicios.views.require_application_permission")
    def test_retention_rejects_deletion_of_protected_operations(self, _):
        response = RetentionPolicyView.as_view()(self.request("post", "/api/technical/retention/", {
            "categoria": "OPERACIONES", "periodo_dias": 365,
            "protege_operaciones": True, "eliminacion_habilitada": True,
        }))
        self.assertEqual(response.status_code, 400)

    @patch("apps.servicios.views.require_application_permission")
    @patch("apps.servicios.views.get_object_or_404")
    def test_deployment_rejects_unapproved_release(self, get_object, _):
        get_object.return_value = SimpleNamespace(id_version=1, version="v2.0", aprobada=False)
        response = DeploymentView.as_view()(self.request("post", "/api/technical/deployments/", {
            "id_version": 1, "confirmacion": "DESPLEGAR v2.0",
        }))
        self.assertEqual(response.status_code, 400)


class ConditioningTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = SimpleNamespace(
            id="00000000-0000-0000-0000-000000000001",
            email="operator@cologistic.com",
            is_authenticated=True,
        )

    def request(self, method, path, data=None):
        request = getattr(self.factory, method)(path, data or {}, format="json")
        force_authenticate(request, user=self.user)
        return request

    @patch("apps.servicios.serializers.Servicio.objects.filter")
    @patch("apps.servicios.serializers.Producto.objects.filter")
    @patch("apps.servicios.serializers.Stock.objects.filter")
    def test_repallet_request_rejects_stock_from_another_client(self, stocks, products, services):
        services.return_value.exists.return_value = False
        stocks.return_value.first.return_value = SimpleNamespace(
            id_stock=7, id_producto=5, cantidad_total=10, cantidad_reservada=0
        )
        products.return_value.first.return_value = SimpleNamespace(id_cliente=99)
        serializer = RepalletRequestSerializer(data={
            "codigo": "REP-001", "id_cliente": 1, "id_stock": 7,
            "descripcion": "Cambio de paleta", "cantidad": "2",
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn("id_stock", serializer.errors)

    @patch("apps.servicios.serializers.Servicio.objects.filter")
    @patch("apps.servicios.serializers.Producto.objects.filter")
    @patch("apps.servicios.serializers.Stock.objects.filter")
    def test_reboxing_derives_client_and_validates_available_stock(self, stocks, products, services):
        services.return_value.exists.return_value = False
        stock = SimpleNamespace(id_stock=8, id_producto=6, cantidad_total=15, cantidad_reservada=3)
        stocks.return_value.first.return_value = stock
        products.return_value.first.return_value = SimpleNamespace(id_cliente=4)
        serializer = ReboxingSerializer(data={
            "codigo": "REN-001", "id_stock": 8, "descripcion": "Caja nueva",
            "cantidad": "5", "cantidad_cajas_origen": 2,
            "cantidad_cajas_destino": 3, "tarifa": "1.50",
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["id_cliente"], 4)
        self.assertIs(serializer.validated_data["stock"], stock)

    @patch("apps.servicios.views.require_application_permission")
    @patch("apps.servicios.views.get_object_or_404")
    def test_execution_rejects_a_non_repallet_service(self, get_object, _):
        get_object.return_value = SimpleNamespace(tipo_servicio="REENCAJADO", estado="COMPLETADO")
        response = RepalletExecutionView.as_view()(self.request(
            "post", "/api/conditioning/services/3/execute-repallet/", {}
        ), service_id=3)
        self.assertEqual(response.status_code, 400)

    @patch("apps.servicios.views.serialize_services")
    @patch("apps.servicios.views.require_application_permission")
    @patch("apps.servicios.views.get_object_or_404")
    def test_completed_service_can_be_sent_to_billing(self, get_object, _, serialize):
        service = SimpleNamespace(
            id_servicio=9, estado="COMPLETADO", estado_facturacion="GENERADO",
            fecha_reporte=None, save=Mock(),
        )
        get_object.return_value = service
        serialize.return_value = [{"id_servicio": 9, "estado_facturacion": "ENVIADO"}]
        response = ConditioningSendBillingView.as_view()(self.request(
            "post", "/api/conditioning/services/9/send-billing/"
        ), service_id=9)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(service.estado_facturacion, "ENVIADO")
        self.assertIsNotNone(service.fecha_reporte)

    @patch("apps.servicios.views.billing_rows")
    def test_conditioning_reports_are_valid_pdf_and_xlsx_files(self, rows):
        rows.return_value = (["Código", "Importe"], [["REP-001", "20.00"]])
        pdf = _conditioning_file("Servicio REP-001", [], "pdf")
        xlsx = _conditioning_file("Servicio REP-001", [], "xlsx")
        self.assertTrue(pdf.content.startswith(b"%PDF-1.4"))
        self.assertTrue(xlsx.content.startswith(b"PK"))


class HealthEndpointTests(SimpleTestCase):
    def test_health_endpoint_returns_ok_without_authentication(self):
        response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(response.content, {"status": "ok", "service": "wms-api"})
