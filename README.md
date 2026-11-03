# Módulo de Autenticación — Laboratorio 4 (Sistemas Distribuidos, UPTC)

Proceso independiente con **su propia base de datos** (PostgreSQL). Guarda usuarios y roles, verifica credenciales
y **es el único que firma los JWT**. El Gateway solo los valida.

Java 17 · Spring Boot 3.3.4 · Spring JDBC · PostgreSQL 16 · Spring Security (BCrypt + OAuth2 Resource Server, HS256)

| Qué | Valor |
|---|---|
| API | puerto **8083** |
| Base de datos | PostgreSQL, puerto **5435** en el host (la 5432/5433/5434 son de Materias, Estudiantes, Inscripciones) |
| Tabla | `users` (`id`, `username`, `password_hash`, `role`, `created_at`) — se crea sola (`schema.sql`) |

## Endpoints (todos bajo `/api/auth`, para que el Gateway los enrute por prefijo)

| Endpoint | Acceso | Notas |
|---|---|---|
| `POST /api/auth/login` | Público | Devuelve `{accessToken, tokenType, expiresIn, user}`. Credenciales malas → `401` |
| `POST /api/auth/register` | **ADMIN** | Crea usuarios con rol `USER`; `estudianteId` opcional. Nombre repetido → `409` |
| `PATCH /api/auth/users/{username}` | **ADMIN** | Vincula un usuario con un estudiante: body `{"estudianteId": 12}` |
| `GET /api/auth/me` | Token | Usuario del token |
| `GET /health` | Público | Health check de la plataforma |
| `/swagger-ui.html` | Público | Documentación |

**Estudiantes:** el usuario se vincula a un estudiante con `estudianteId` (columna `users.estudiante_id`, solo el id, sin
foreign key entre módulos). El login lo incluye en el token como claim `estudianteId`; el frontend y el Gateway lo leen de ahí.

Las contraseñas se guardan con **BCrypt**. El usuario `ADMIN` inicial se crea al arrancar con `ADMIN_USERNAME` / `ADMIN_PASSWORD`
(si ya existe en la base, no se toca).

El módulo valida el JWT por su cuenta en `register` y `me`, así que sigue protegido aunque la plataforma lo exponga
(requisito 7.1 del Lab 4: «si los expone públicamente, deben exigir autenticación»).

## Levantar el entorno local

```bash
cp .env.example .env        # edita DB_PASSWORD, JWT_SECRET, ADMIN_PASSWORD
```

**Opción A — todo en Docker (BD + API):**
```bash
docker compose up -d --build
```

**Opción B — BD en Docker y la API desde el IDE/Maven:**
```bash
docker compose up -d auth-db
# bash
set -a; source .env; set +a
DB_URL=jdbc:postgresql://localhost:5435/auth_db mvn spring-boot:run
```
```powershell
# PowerShell
docker compose up -d auth-db
$env:DB_PASSWORD="..."; $env:JWT_SECRET="..."; $env:ADMIN_PASSWORD="..."; mvn spring-boot:run
```
(Con el usuario/base por defecto no hace falta `DB_URL`: ya apunta a `localhost:5435/auth_db`.)

Prueba rápida:
```bash
curl -s -X POST localhost:8083/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"TU_CLAVE_ADMIN"}'
```

## Conexión con el Gateway

1. `JWT_SECRET` (y, si los cambias, `JWT_ISSUER` / `JWT_AUDIENCE`) deben ser **idénticos** en este módulo y en el Gateway.
2. En el Gateway: `AUTH_URL=http://localhost:8083` (en la nube, la URL interna de este servicio).
3. El Gateway enruta `/api/auth/**` hacia aquí; el cliente solo habla con el Gateway.

## En la nube (Lab 4)

- Imagen: `docker build -t auth-service .` → publicar en el registro del proveedor.
- BD: una base (`auth_db`) con usuario y contraseña propios en el servicio PostgreSQL administrado; `DB_URL`, `DB_USER`, `DB_PASSWORD`,
  `JWT_SECRET` y `ADMIN_PASSWORD` van en el gestor de secretos / variables del servicio, nunca en git ni en la imagen.
- Health check de la plataforma: `GET /health` (puerto 8083).
- Si el cómputo expone el servicio públicamente, deja documentada la decisión (ya exige token en `register` y `me`).

## Pruebas

`mvn test` — `TokenServiceTest` (unitaria, sin BD): el token emitido se verifica con la misma clave y trae rol y vencimiento.
