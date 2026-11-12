from django.db import migrations


CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS usuarios.credencial (
    id_usuario uuid PRIMARY KEY
        REFERENCES usuarios.usuario (id_usuario) ON DELETE CASCADE,
    password_hash varchar(255) NOT NULL,
    debe_cambiar_password boolean NOT NULL DEFAULT false,
    intentos_fallidos integer NOT NULL DEFAULT 0,
    bloqueado_hasta timestamptz,
    ultimo_acceso timestamptz,
    fecha_actualizacion timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usuarios.sesion (
    id_sesion uuid PRIMARY KEY,
    id_usuario uuid NOT NULL
        REFERENCES usuarios.usuario (id_usuario) ON DELETE CASCADE,
    token_hash char(64) NOT NULL UNIQUE,
    fecha_creacion timestamptz NOT NULL DEFAULT now(),
    fecha_expiracion timestamptz NOT NULL,
    fecha_revocacion timestamptz,
    reemplazada_por uuid,
    ip varchar(45),
    user_agent varchar(255)
);

CREATE INDEX IF NOT EXISTS idx_sesion_id_usuario
    ON usuarios.sesion (id_usuario);
"""


DROP_TABLES_SQL = """
DROP INDEX IF EXISTS usuarios.idx_sesion_id_usuario;
DROP TABLE IF EXISTS usuarios.sesion;
DROP TABLE IF EXISTS usuarios.credencial;
"""


# One-time import of the bcrypt hashes exported from Supabase Auth. Django's
# BCryptPasswordHasher stores them as "bcrypt$<hash>" and they are re-hashed to
# PBKDF2 on the first successful login. The export table is optional.
IMPORT_SUPABASE_HASHES_SQL = """
DO $$
BEGIN
    IF to_regclass('usuarios.supabase_auth_export') IS NOT NULL THEN
        INSERT INTO usuarios.credencial (
            id_usuario, password_hash, debe_cambiar_password,
            fecha_actualizacion
        )
        SELECT u.id_usuario, 'bcrypt$' || e.encrypted_password, false, now()
        FROM usuarios.supabase_auth_export e
        JOIN usuarios.usuario u ON u.id_usuario = e.id
        WHERE e.encrypted_password LIKE '$2%'
        ON CONFLICT DO NOTHING;
    END IF;
END $$;
"""


class Migration(migrations.Migration):
    dependencies = []

    operations = [
        migrations.RunSQL(CREATE_TABLES_SQL, DROP_TABLES_SQL),
        migrations.RunSQL(
            IMPORT_SUPABASE_HASHES_SQL, migrations.RunSQL.noop
        ),
    ]
