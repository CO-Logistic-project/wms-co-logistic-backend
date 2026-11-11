from getpass import getpass

from django.core.management.base import BaseCommand, CommandError
from rest_framework.exceptions import ValidationError

from apps.usuarios.local_auth import set_password
from apps.usuarios.models import Usuario


class Command(BaseCommand):
    help = (
        "Define la contraseña de un usuario existente (p. ej. el primer "
        "administrador). Revoca sus sesiones activas."
    )

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument(
            "--temporal",
            action="store_true",
            help="Obliga al usuario a cambiar la contraseña al iniciar sesión.",
        )

    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        try:
            user = Usuario.objects.get(correo__iexact=email)
        except Usuario.DoesNotExist as exc:
            raise CommandError(f"No existe un perfil WMS para {email}.") from exc

        password = getpass("Nueva contraseña: ")
        if password != getpass("Repite la contraseña: "):
            raise CommandError("Las contraseñas no coinciden.")

        try:
            set_password(
                user.id_usuario, password, must_change=options["temporal"], user=user
            )
        except ValidationError as exc:
            messages = [m for msgs in exc.detail.values() for m in msgs]
            raise CommandError("\n".join(str(m) for m in messages)) from exc

        suffix = " (deberá cambiarla al ingresar)" if options["temporal"] else ""
        self.stdout.write(self.style.SUCCESS(f"Contraseña actualizada{suffix}."))
