# Secure File Scanner API

REST API for uploading files and statically analyzing them for risk indicators: dangerous or disguised
file names, executables hiding behind harmless extensions, credentials, potential personal data and
suspicious ZIP archives. Each scan produces findings and a 0–100 risk score with a LOW / MEDIUM / HIGH /
CRITICAL level.

> Проект является учебным security-oriented scanner API и не заменяет промышленный антивирус, sandbox или полноценную систему malware analysis.
>
> This is an educational, security-oriented scanner API. It does not replace an industrial antivirus, a sandbox or a full malware-analysis system.

> Uploaded files are analyzed statically and are never executed by the application.

Built with FastAPI, SQLAlchemy 2.x, PostgreSQL, Alembic, Redis, Celery, JWT and Docker Compose.

## Features

- **Authentication**: registration, login, JWT access tokens, bcrypt password hashing.
- **RBAC**: `USER` and `ADMIN` roles enforced by FastAPI dependencies; the role is read from the database
  on every request (never trusted from the token).
- **Safe uploads**: streamed to disk with a size limit, stored under a random UUID name inside one
  configured directory, SHA-256 computed, real file type detected from content (magic bytes), the
  client-supplied `Content-Type` is only recorded.
- **Five scanners** behind one `BaseScanner` interface:
  `filename` (dangerous extensions, double extensions, suspicious names, hidden extensions, declared-MIME mismatch),
  `file_type` (extension vs. real content), `secrets` (API keys, tokens, private-key markers, password/secret assignments),
  `pii` (email, phone, INN, SNILS, passport-like, bank card, bank account, IP, simple addresses; checksum-validated where possible),
  `archive` (ZIP file count, total size, nesting depth, zip-bomb ratio, zip-slip paths, dangerous entries).
- **Risk engine**: `severity weight × confidence × rule factor`, aggregated per rule with diminishing returns and
  combined across rules as independent evidence, capped at 100.
- **Background processing**: Celery + Redis. Scan lifecycle: `QUEUED → RUNNING → COMPLETED | FAILED | REJECTED`.
- **Audit log** for security-relevant actions; reading the audit log is itself audited.
- **Rate limiting** (Redis): login per IP, uploads per user.
- **Request IDs** (`X-Request-ID`), structured logs, one error format for every failure.
- **Admin**: list users, all scans, audit log, delete suspicious files, platform statistics (`/api/v1/stats`).

## Architecture

```
Client ──HTTP──> FastAPI (app) ──> PostgreSQL   users, files, scans, findings, audit_logs
                    │   │
                    │   └── Redis  rate limiting
                    │
                    └── enqueue ──> Redis (broker) ──> Celery worker
                                                           │ runs scanners (static analysis only)
                                                           │ risk engine, saves findings
                                                           └──> PostgreSQL
            uploaded files: shared volume, random names, mode 0600
```

Flow: `POST /files` (validate → stream to disk → hash → detect type → DB row) → `POST /scans` (QUEUED row + Celery task)
→ worker marks `RUNNING`, runs all scanners, computes the risk score, stores findings → `COMPLETED`
(`REJECTED` if an archive limit is exceeded, `FAILED` with a short sanitized message on errors).

Layers: `api/` (HTTP only) → `services/` (business logic) → `scanners/`, `db/`, `utils/`. Scanners know nothing
about HTTP or the database; they receive a `ScanContext` and return `Finding` objects.

## Security model

| Threat | Mitigation |
|---|---|
| Executing uploaded files | Never done. No `exec`/`eval`/`os.system`/`subprocess` in the application; a test enforces this by AST scan and by blocking process-spawning functions during scans. |
| Path traversal | Files are stored as `<uuid hex>` inside one directory; client file names are only metadata (cleaned of path components and control characters). Resolved paths must stay inside the storage root (symlinks rejected). |
| Disguised executables | Real type detected from content; `TYPE_MISMATCH`, `DOUBLE_EXTENSION`, `HIDDEN_EXTENSION` (e.g. right-to-left override) findings. |
| Oversized uploads | Early rejection from `Content-Length`, plus a hard limit while streaming; partial files are removed. |
| Zip bombs / archive abuse | Limits for entries, declared size, nesting depth and compression ratio; nothing is extracted to disk; exceeding a limit rejects the scan. |
| Secret leakage | Only masked evidence is stored (`****abc` for long values, nothing for short ones, no sample for private keys). Audit details drop sensitive keys. Secrets never appear in logs or responses. |
| Password/JWT weaknesses | bcrypt, 10–72 byte passwords (bcrypt truncates silently beyond 72 bytes), HS256/384/512 only, `exp`/`iat`/`sub` required, role not in token, production refuses a default or short `JWT_SECRET`. |
| User enumeration | Identical 401 for unknown email, wrong password and disabled account; hash verified in all cases. Foreign resources return 404, same as missing ones. |
| Brute force / abuse | Redis rate limits on login (5/min/IP) and uploads (20/min/user), `429` with `Retry-After`. |
| Information disclosure | Unified error format, no tracebacks in responses, validation errors do not echo submitted values, scan errors are short fixed messages. |
| Privilege escalation | Role cannot be chosen at registration (`extra="forbid"`); admins are created only via CLI. |

## API

Interactive docs: `/docs` (Swagger UI) and `/redoc`. All endpoints except `/health*`, register and login need
`Authorization: Bearer <token>`.

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Create a USER account |
| POST | `/api/v1/auth/login` | Obtain a JWT (rate limited) |
| GET | `/api/v1/auth/me` | Current user |
| POST | `/api/v1/files` | Upload a file (multipart, field `file`) |
| GET | `/api/v1/files` | List my files |
| GET | `/api/v1/files/{file_id}` | File metadata, never content (status, risk level) |
| DELETE | `/api/v1/files/{file_id}` | Delete file, scans and findings (owner or admin) |
| POST | `/api/v1/scans` | Start a scan (`202`, status `QUEUED`) |
| GET | `/api/v1/scans` | List my scans (`?status=`) |
| GET | `/api/v1/scans/{scan_id}` | Scan status, score and level |
| GET | `/api/v1/scans/{scan_id}/findings` | Findings, most severe first |
| GET | `/api/v1/admin/users` | **Admin** – users |
| GET | `/api/v1/admin/scans` | **Admin** – all scans (`?status=&risk_level=`) |
| GET | `/api/v1/admin/audit` | **Admin** – audit log (`?action=&user_id=`) |
| GET | `/api/v1/stats` | **Admin** – totals, high/critical/failed scans, average scan time |
| GET | `/health` | Liveness |
| GET | `/health/ready` | Readiness (PostgreSQL + Redis), `503` if a dependency is down |

Errors always look like:

```json
{"error": {"code": "FILE_TOO_LARGE", "message": "File exceeds configured size limit"}}
```

Codes in use: `BAD_REQUEST`, `EMPTY_FILE`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `FILE_TOO_LARGE`,
`VALIDATION_ERROR` (with `details`), `RATE_LIMITED`, `QUEUE_UNAVAILABLE`, `INTERNAL_ERROR`.

### Findings and scoring

Finding fields: `scanner`, `rule`, `severity`, `description`, `evidence` (masked), `confidence`.
Severity weights: LOW 10, MEDIUM 30, HIGH 60, CRITICAL 90. Levels: 0–19 LOW, 20–49 MEDIUM, 50–79 HIGH, 80–100 CRITICAL.

```
finding_score = severity_weight × confidence × rule_factor
per rule:   best hit counts 100%, second 50%, third 25%, the rest is ignored
total       = 100 × (1 − Π(1 − score_i / 100))            # never above 100
```

One strong indicator is not diluted by clean checks, several weak indicators add up, and repeating the same
weak rule a hundred times cannot reach CRITICAL. Rule factors lower weak hints (`SUSPICIOUS_NAME`,
`DECLARED_MIME_MISMATCH`) and PII rules (potential PII has many false positives).

## Installation

Requirements: Python 3.11+ (tested on 3.11 and 3.12), PostgreSQL 14+, Redis 6+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt          # or requirements.txt for runtime only
cp .env.example .env     # then edit: DATABASE_URL/REDIS_URL hosts (localhost), STORAGE_PATH=./storage, JWT_SECRET
python -c "import secrets; print(secrets.token_urlsafe(48))"   # use as JWT_SECRET

alembic upgrade head
uvicorn app.main:app --reload                                  # API on :8000
celery -A app.workers.celery_app.celery_app worker --loglevel=INFO   # second terminal
```

Create the first administrator (the password is read from `ADMIN_PASSWORD` or prompted, never taken from arguments):

```bash
python -m app.cli create-admin --email admin@example.com
```

For quick local experiments without a worker set `CELERY_TASK_ALWAYS_EAGER=true`
(scans then run inside the API process; do not use in production).

## Docker

```bash
cp .env.example .env     # set JWT_SECRET; the default host names already match docker-compose
docker compose up --build
```

Services: `db` (PostgreSQL 16), `redis`, `migrate` (one-shot `alembic upgrade head`), `app` (port 8000),
`worker` (Celery). `app` and `worker` share a volume for uploaded files and run as an unprivileged user.
Compose refuses to start without `JWT_SECRET`.

```bash
docker compose run --rm -e ADMIN_PASSWORD='choose-a-strong-password' app \
    python -m app.cli create-admin --email admin@example.com
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `production` rejects a default/short `JWT_SECRET` |
| `DATABASE_URL` | `postgresql+asyncpg://scanner:scanner@db:5432/scanner` | SQLAlchemy async URL |
| `REDIS_URL` | `redis://redis:6379/0` | Celery broker and rate limiter |
| `JWT_SECRET` | `change-me-in-production` | **Required in production**, at least 32 random characters |
| `JWT_ALGORITHM` | `HS256` | `HS256`, `HS384` or `HS512` only |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Token lifetime |
| `BCRYPT_ROUNDS` | `12` | bcrypt cost (4–16) |
| `MAX_FILE_SIZE_MB` | `10` | Upload limit |
| `STORAGE_PATH` | `./storage` (`/data/storage` in Docker) | Directory for uploaded files |
| `RATE_LIMIT_LOGIN` | `5` | Login attempts per minute per IP |
| `RATE_LIMIT_UPLOAD` | `20` | Upload requests per minute per user |
| `MAX_ARCHIVE_FILES` | `500` | Max entries in an archive (cumulative over nested archives) |
| `MAX_EXTRACTED_SIZE_MB` | `100` | Max declared uncompressed size |
| `MAX_ARCHIVE_DEPTH` | `2` | Max nesting depth of archives |
| `SCAN_TIME_LIMIT_SECONDS` | `300` | Celery soft time limit per scan |
| `CELERY_TASK_ALWAYS_EAGER` | `false` | Run tasks inline (development only) |
| `LOG_LEVEL` | `INFO` | Python logging level |

## Database migrations

Tables are never created at application start; Alembic owns the schema.

```bash
alembic upgrade head        # apply
alembic downgrade -1        # roll back one revision
alembic revision --autogenerate -m "describe change"
alembic check               # fails if models and migrations differ (also run in CI)
```

## Running tests

```bash
pytest                                  # ~380 tests, SQLite in memory, no external services
INTEGRATION_DATABASE_URL=postgresql+asyncpg://scanner:scanner@localhost:5432/scanner \
INTEGRATION_REDIS_URL=redis://localhost:6379/0 \
    pytest tests/test_integration.py    # real PostgreSQL + Redis (after `alembic upgrade head`)
```

Coverage: authentication and JWT edge cases (expired, forged, `alg=none`, tampered, wrong secret), RBAC, upload
limits, path traversal, hashing and type detection, every scanner including false-positive checks, risk
calculation, the full scan lifecycle including failures, the admin API, audit-log hygiene, and the ten
security checks from the specification (`tests/test_security.py`). All test "secrets" are obviously fake and are
assembled at runtime so the repository contains no credential-like strings.

GitHub Actions (`.github/workflows/tests.yml`) runs on Python 3.11 and 3.12 with PostgreSQL and Redis service
containers: import check, `alembic upgrade head`, `alembic check`, downgrade/upgrade round-trip, then pytest including the integration tests.

## Example workflow

```bash
BASE=http://localhost:8000

# 1. register and log in
curl -s -X POST $BASE/api/v1/auth/register -H 'Content-Type: application/json' \
     -d '{"email":"me@example.com","password":"a-long-passphrase-123"}'
TOKEN=$(curl -s -X POST $BASE/api/v1/auth/login -H 'Content-Type: application/json' \
     -d '{"email":"me@example.com","password":"a-long-passphrase-123"}' | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. upload a file
FILE_ID=$(curl -s -X POST $BASE/api/v1/files -H "Authorization: Bearer $TOKEN" \
     -F "file=@./report.pdf.exe" | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 3. start a scan
SCAN_ID=$(curl -s -X POST $BASE/api/v1/scans -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d "{\"file_id\":\"$FILE_ID\"}" \
     | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 4. poll the result, then read findings
curl -s $BASE/api/v1/scans/$SCAN_ID -H "Authorization: Bearer $TOKEN"
curl -s $BASE/api/v1/scans/$SCAN_ID/findings -H "Authorization: Bearer $TOKEN"
```

Typical result for a Windows executable named `report.pdf.exe`: status `COMPLETED`, `DOUBLE_EXTENSION` and
`DANGEROUS_EXTENSION` findings, risk score 80, level `CRITICAL`.

## Project structure

```
app/
  main.py                 app factory, request-ID middleware, routers
  cli.py                  create-admin command
  api/                    deps (auth, RBAC, rate limits), auth, files, scans, admin(+stats), health
  core/                   config (pydantic-settings), security (bcrypt, JWT), logging, exceptions
  db/                     database (async engine), models
  schemas/                Pydantic request/response models
  services/               auth, file, scan, risk, audit, rate_limit
  scanners/               base, filename, file_type, secrets, pii, archive
  workers/                celery_app, scan_tasks
  utils/                  hashing, storage (safe paths), filetype (magic-byte detection)
alembic/                  migrations (versions/0001_initial_schema.py)
tests/                    unit, API, security and integration tests
Dockerfile, docker-compose.yml, .env.example, requirements*.txt, pytest.ini
.github/workflows/tests.yml
```

## Limitations

- **Not an antivirus.** There are no malware signatures, no sandbox, no behavioral analysis. Findings are heuristics
  and can be wrong in both directions; a CRITICAL score means "suspicious indicators", not "malware".
- Type detection covers common formats only (PE, ELF, Mach-O, Java class, ZIP/Office, PDF, PNG, JPEG, GIF, gzip, 7z, RAR, text).
  Only **ZIP** archives are inspected; other archives are only identified. Encrypted archive entries cannot be inspected.
- Secret and PII scanners read **text files only**, at most the first 5 MB. PII detection is pattern/checksum based
  and always reported as *potential* PII; Russian formats (INN, SNILS, passport, phone) are the most thorough.
- **Rate limiter fails open**: if Redis is unreachable requests are allowed (and a warning is logged), so a Redis
  outage disables brute-force protection but does not lock users out. It uses a fixed window and the socket IP;
  `X-Forwarded-For` is deliberately not trusted, so behind a reverse proxy all clients share the proxy's IP unless
  you add trusted-proxy handling.
- **Request-size limit is best-effort inside the app.** An oversized upload is rejected from `Content-Length` and while
  copying to disk, but Starlette buffers multipart bodies (spooled temp files) before the handler runs, so a chunked upload
  without `Content-Length` can still consume temporary disk space. Put a body-size limit in the reverse proxy
  (for example nginx `client_max_body_size`) in production.
- Registration returns `409` for an existing email, which reveals that the address is registered.
- JWT access tokens only: no refresh tokens and no server-side revocation (deactivating a user does take effect immediately).
- The service speaks plain HTTP; terminate TLS in front of it. No CORS is configured.
- Uploaded files are stored on a local/shared volume, not in object storage, and are not encrypted at rest.
- Test suite runs on SQLite; PostgreSQL behavior is verified by the integration tests in CI.

## Future improvements

- Optional ClamAV / YARA integration as additional scanners.
- Refresh tokens with revocation, account lockout and email verification.
- Support for tar/gzip/7z inspection and Office macro detection.
- Object storage (S3-compatible) and encryption at rest; retention policy for old files.
- Prometheus metrics, OpenTelemetry tracing, structured JSON logging.
- Trusted-proxy handling and a sliding-window rate limiter.
- Export of scan results as JSON/PDF.

## Disclaimer

Educational project. It is provided as is, without warranty, and must not be relied on as the only protection against
malicious files. Do not upload real credentials or personal data to a test deployment.
