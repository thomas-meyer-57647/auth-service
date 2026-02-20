# auth-service
Multi-Tenant Auth-Service (Spring Boot, MariaDB) mit JWT/JWKS, verpflichtender 2FA, Social Login und Refresh-Sessions (24h oder “dauerhaft”).

## Docker build/run
Build image:
```bash
docker build -t auth-service:latest .
```

Run container:
```bash
docker run --rm -p 8080:8080 --name auth-service auth-service:latest
```

## Docker Compose
Start all services (DB + app):
```bash
docker compose up --build
```

Expected URLs:
- Swagger UI: `http://localhost:8080/swagger-ui.html`
- Actuator Health: `http://localhost:8080/actuator/health`

## Environment Variables
- `AUTH_DB_HOST` (default: `localhost`)
- `AUTH_DB_PORT` (default: `3306`)
- `AUTH_DB_NAME` (default: `auth`)
- `AUTH_DB_USER` (default: `root`)
- `AUTH_DB_PASSWORD` (default: empty)
- `AUTHPORT` (default: `8080`)

## IntelliJ Run Configuration
Example `Environment variables`:
`AUTH_DB_HOST=localhost;AUTH_DB_PORT=3306;AUTH_DB_NAME=auth;AUTH_DB_USER=root;AUTH_DB_PASSWORD=;AUTHPORT=8080`

Hinweis: `Include system environment variables` kann aktiviert bleiben, da die Variablen service-spezifisch sind.

Troubleshooting:
- DB connection fails:
  - Ensure `mariadb` container is healthy (`docker compose ps`).
  - Check datasource host is `mariadb` in Docker profile.
- Flyway issues:
  - Verify migration exists at `src/main/resources/db/migration/V1__init.sql`.
  - Recreate DB volume if schema is inconsistent: `docker compose down -v` then `docker compose up --build`.
- Root empty password (dev only):
  - Compose uses `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=yes` and `root` with empty password.
  - Do not use this setup for production.
