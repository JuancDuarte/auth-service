-- Esquema del módulo de Autenticación (idempotente: se ejecuta en cada arranque).
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL    PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(100) NOT NULL,                       -- solo hash BCrypt, nunca la contraseña
    role          VARCHAR(20)  NOT NULL CHECK (role IN ('ADMIN', 'USER')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Vínculo opcional con un estudiante del módulo Estudiantes (solo el id; sin foreign key entre módulos).
-- Idempotente: también actualiza una base creada antes de este cambio.
ALTER TABLE users ADD COLUMN IF NOT EXISTS estudiante_id BIGINT;

-- Los nombres de usuario no distinguen mayúsculas.
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username_lower ON users (lower(username));
