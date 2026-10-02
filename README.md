# TwynIX Proxy

TwynIX Proxy is an on-prem Node.js service that sits between an HMI/frontend, ThingsBoard, and Apache IoTDB. It is designed for industrial deployments where ThingsBoard remains the system of record, while this proxy adds stricter control-side policy enforcement, audit logging, and operational guardrails.

The service is intended to run inside a trusted factory or plant network. It should not be exposed directly to the public internet.

## What It Does

- Proxies allowlisted ThingsBoard HTTP and WebSocket routes.
- Validates user JWTs with ThingsBoard before protected operations.
- Delegates device RPC authorization to ThingsBoard's native RPC Call permission using the caller's token. Other attribute-based guards (for example shared-attribute writes) remain unchanged.
- Restricts ThingsBoard RPC calls by method, tag, payload shape, timeout, and rate.
- Blocks unsafe telemetry writes while allowing controlled shared/server-scope flows.
- Provides OPC UA gateway service routes for browse, discovery, and config apply.
- Provides read-oriented IoTDB trend and schema endpoints with bounded query behavior.
- Persists global alarm shelving state in SQLite.
- Emits audit/oplog events with optional HMAC signatures.
- Exposes health, status, and lightweight metrics endpoints.

## Architecture

```text
HMI / frontend
      |
      v
TwynIX Proxy :8787
      |
      +--> ThingsBoard REST / WebSocket
      +--> ThingsBoard server-side RPC to gateways
      +--> Apache IoTDB REST API
      +--> local SQLite shelving database
```

ThingsBoard owns authentication, read-side RBAC, and device RPC authorization. This proxy retains payload policies, rate limits, auditing and guards for custom write paths. RPC no longer reads `SERVER_SCOPE.security.permissions.control`.

## Repository Layout

```text
app.js                     Main Express application and proxy wiring
src/security-policy.js     Proxy allowlist, header scrubbing, query checks
src/rpc-policy.js          RPC method/tag/parameter validation
src/telemetry-write-policy.js
                            Telemetry write guard
src/iotdb-trend-query.js   Bounded IoTDB trend query implementation
src/iotdb-schema.js        IoTDB schema endpoint
src/twynix-oplog.js        Audit/oplog persistence
src/config-validation.js   Startup config validation
src/config-secrets.js      Env/file-based secret loading
test/                      Node test suite
Dockerfile                 Production container image
DEPLOYMENT_HARDENING.md    Additional hardening notes
```

## Requirements

- Node.js 20 or newer for local development.
- Docker for container deployment.
- Reachable ThingsBoard instance.
- Reachable Apache IoTDB instance if IoTDB routes are enabled.
- A dedicated ThingsBoard tenant-admin service account for proxy-side server attribute reads.

## Local Development

Install dependencies:

```bash
npm ci
```

Run tests:

```bash
npm test
```

Run locally:

```bash
npm start
```

The service listens on port `8787` by default.

## Configuration

### Twin configuration and Rule Chain provisioning routes

Twin deployment and Factory availability provisioning permit these exact authenticated POST routes:

- `/api/ruleChain` — create or update a Rule Chain.
- `/api/ruleChain/metadata` — save its nodes and connections.
- `/api/calculatedField/testScript` — validate a calculated-field script.
- `/api/alarm/rule/testScript` — validate an alarm condition script.
- `/api/calculatedField` — create or update the compiled calculated field or alarm.

All five also pass the management-write JWT validation and audit middleware.
They require `TENANT_ADMIN` and membership in `MGMT_ALLOWED_ROLES`; broader
management-role configuration does not relax the tenant-admin requirement.
Requests retain the caller's token, so ThingsBoard enforces tenant and entity
authorization. No service-account token is substituted.

The existing authenticated GET policy covers field listings, relations and the
deployment manifest. Relation and server-attribute writes retain their existing
management policies. Calculated-field deletion, recalculation and other write
endpoints are not enabled by this change. Rule Chain deletion, bulk import and
script-test write routes remain denied; only the two exact save endpoints are added.

Rebuild/restart the deployed proxy from this revision for the route change to
take effect; changing the frontend alone cannot update the running allowlist.
First verify **Preview deployment**. Deploying a twin remains a separate,
explicit operation that can activate calculations and alarms.

Configuration is read from environment variables. In production, prefer file-based secrets using `*_FILE` variables.

Required core settings:

```env
NODE_ENV=production
PORT=8787
THINGSBOARD_URL=https://thingsboard.example.local
TB_ADMIN_USERNAME=twynix-proxy-service@example.local
TB_ADMIN_PASSWORD_FILE=/run/secrets/tb_admin_password
IOTDB_URL=http://iotdb.example.local:18080
IOTDB_AUTH_FILE=/run/secrets/iotdb_auth
INTERNAL_PROXY_SECRET_FILE=/run/secrets/internal_proxy_secret
AUDIT_HMAC_SECRET_FILE=/run/secrets/audit_hmac_secret
CORS_ORIGINS=https://hmi.example.local
```

Recommended production control settings:

```env
RPC_ACL_ENABLED=true
RPC_ALLOWED_METHODS=writeTag
RPC_ALLOWED_TAGS=pump.speed,pump.enabled
RPC_REQUIRE_AUDIT=false
IOTDB_QUERY_ENABLED=false
```

Use `RPC_METHOD_PARAM_RULES` to constrain RPC payloads:

```env
RPC_METHOD_PARAM_RULES={"writeTag":{"required":["tag","value"],"allowedKeys":["tag","value"],"types":{"tag":"string","value":"number"},"ranges":{"value":{"min":0,"max":100}}}}
```

Important production guardrails:

- `RPC_ACL_ENABLED=false` is rejected when `NODE_ENV=production`.
- `RPC_ACL_ENABLED` is retained as the legacy configuration name for the RPC transport guard, not the old attribute ACL. Keep it `true`; disabling it blocks RPC routes even in development. Both `/api/plugins/rpc/{oneway|twoway}/{deviceId}` and `/api/rpc/{oneway|twoway}/{deviceId}` require the guard.
- Before deploying this branch against ThingsBoard 4.4, migrate existing control users into appropriately scoped ThingsBoard roles/entity groups with **RPC Call** permission. Review inherited/default roles: broad defaults may grant more access than the old ACL. Test an allowed user, a denied user, another device group, and another tenant against a non-production device.
- Requests are forwarded with the user's token, never an administrator token. Upstream status/body are preserved, including 401/403. Pre-forward audit records say `forwarded`, not authorized; response records capture the upstream HTTP outcome, not physical equipment state. A failed response audit cannot undo a command already sent. Required pre-forward audit still fails closed.
- RPC method/tag/parameter restrictions remain in effect (the default method is still `writeTag`). Native RPC Call permission is device-level authorization; it does not replace method restrictions, equipment interlocks or safe operating limits.
- `AUDIT_HMAC_SECRET` or `AUDIT_HMAC_SECRET_FILE` is required when `NODE_ENV=production`.
- `IOTDB_QUERY_ENABLED` defaults to disabled.
- `PROXY_MAX_BODY_BYTES` limits proxied write request size and defaults to `1048576`.
- Secrets must not be committed, copied into images, or placed directly in production `.env` files.

## Secrets

The application supports both direct env values and file-based secrets. Use file-based secrets in production:

```env
TB_ADMIN_PASSWORD_FILE=/run/secrets/tb_admin_password
IOTDB_AUTH_FILE=/run/secrets/iotdb_auth
INTERNAL_PROXY_SECRET_FILE=/run/secrets/internal_proxy_secret
AUDIT_HMAC_SECRET_FILE=/run/secrets/audit_hmac_secret
```

The repository ignores `.env`, `secrets/`, `data/`, local database files, logs, and `node_modules/`. The Docker build context also excludes these files through `.dockerignore`.

Rotate any secret that was ever stored locally, copied to another machine, or included in an image build before these ignore rules were in place.

## Docker Build

Build the image:

```bash
docker build --no-cache -t twynix-proxy:1.0.0 .
```

The Dockerfile:

- uses `node:20-alpine`
- installs production dependencies with `npm ci --omit=dev`
- runs as the non-root `node` user
- exposes port `8787`
- includes a `/health` healthcheck

## Docker Run

Create a production environment file without secret values:

```env
NODE_ENV=production
PORT=8787
THINGSBOARD_URL=https://thingsboard.example.local
TB_ADMIN_USERNAME=twynix-proxy-service@example.local
IOTDB_URL=http://iotdb.example.local:18080
CORS_ORIGINS=https://hmi.example.local
RPC_ACL_ENABLED=true
RPC_ALLOWED_METHODS=writeTag
RPC_ALLOWED_TAGS=pump.speed,pump.enabled
IOTDB_QUERY_ENABLED=false
TB_ADMIN_PASSWORD_FILE=/run/secrets/tb_admin_password
IOTDB_AUTH_FILE=/run/secrets/iotdb_auth
INTERNAL_PROXY_SECRET_FILE=/run/secrets/internal_proxy_secret
AUDIT_HMAC_SECRET_FILE=/run/secrets/audit_hmac_secret
```

Run with hardened container settings:

```bash
docker run -d \
  --name twynix-proxy \
  --restart unless-stopped \
  --read-only \
  --tmpfs /tmp \
  --mount type=volume,src=twynix-proxy-data,dst=/app/data \
  --mount type=bind,src=/secure/secrets/tb_admin_password,dst=/run/secrets/tb_admin_password,readonly \
  --mount type=bind,src=/secure/secrets/iotdb_auth,dst=/run/secrets/iotdb_auth,readonly \
  --mount type=bind,src=/secure/secrets/internal_proxy_secret,dst=/run/secrets/internal_proxy_secret,readonly \
  --mount type=bind,src=/secure/secrets/audit_hmac_secret,dst=/run/secrets/audit_hmac_secret,readonly \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file ./production.env \
  -p 8787:8787 \
  twynix-proxy:1.0.0
```

For production, place the container behind a TLS reverse proxy or firewall and restrict inbound access to trusted HMI and engineering hosts.

## Docker Compose Example

```yaml
services:
  twynix-proxy:
    image: twynix-proxy:1.0.0
    restart: unless-stopped
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    ports:
      - "8787:8787"
    env_file:
      - ./production.env
    tmpfs:
      - /tmp
    volumes:
      - twynix-proxy-data:/app/data
      - /secure/secrets/tb_admin_password:/run/secrets/tb_admin_password:ro
      - /secure/secrets/iotdb_auth:/run/secrets/iotdb_auth:ro
      - /secure/secrets/internal_proxy_secret:/run/secrets/internal_proxy_secret:ro
      - /secure/secrets/audit_hmac_secret:/run/secrets/audit_hmac_secret:ro

volumes:
  twynix-proxy-data:
```

## Operational Endpoints

Basic liveness:

```text
GET /health
```

Protected diagnostics, requiring a valid tenant-admin user token:

```text
GET /twynix/status
```

Prometheus-style lightweight metrics, requiring a valid tenant-admin user token:

```text
GET /twynix/metrics
```

Monitor at least:

- ThingsBoard admin login failures
- ThingsBoard and IoTDB connectivity errors
- audit/oplog write failures
- HTTP 5xx rate
- RPC denied/error spikes
- shelving database volume usage

## Production Readiness Checklist

Before tagging a production release:

```bash
npm ci
npm test
npm audit --omit=dev
node --check app.js
docker build --no-cache -t twynix-proxy:1.0.0 .
```

Also complete:

- Rotate all production secrets.
- Confirm no secrets are present in Git history or Docker image layers.
- Run a staging integration test with ThingsBoard, IoTDB, OPC UA gateway, and HMI.
- Run representative load and 24-72 hour soak tests.
- Verify outage and recovery behavior for ThingsBoard and IoTDB.
- Configure backup/restore for the `/app/data` volume if shelving state matters.
- Scan the final container image.
- Document rollback and key rotation procedures.

## Security Notes

- Do not expose this service directly to the internet.
- Restrict inbound access to trusted hosts and network zones.
- Restrict outbound access to only ThingsBoard and IoTDB where possible.
- Keep ThingsBoard service account credentials server-side only.
- Use narrow `RPC_ALLOWED_TAGS` and `RPC_METHOD_PARAM_RULES` in production.
- Keep `AUDIT_HMAC_SECRET` stable enough to validate historical audit entries, and document rotation windows.

## License

This project is licensed under the Apache License 2.0. See `LICENSE`.
