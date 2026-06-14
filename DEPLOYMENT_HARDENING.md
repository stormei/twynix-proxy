# On-Prem Deployment Hardening

This proxy is intended to run on a factory-floor/on-prem network as a ThingsBoard CE RPC security gate. It is not a SCADA replacement and should not be exposed directly to the internet.

## Security Model

- ThingsBoard remains responsible for normal application authentication and read-side RBAC.
- The proxy adds missing control-side RBAC for RPC calls.
- The proxy uses a dedicated ThingsBoard tenant-admin service account only server-side to read `SERVER_SCOPE.security`.
- Clients must never receive the service account password or admin token.
- RPC calls fail closed when user/device security policy is missing or invalid.

## Required Production Settings

Use file-based secrets instead of plaintext values where possible:

```env
TB_ADMIN_USERNAME=twynix-proxy-service@factory.local
TB_ADMIN_PASSWORD_FILE=/run/secrets/tb_admin_password
IOTDB_AUTH_FILE=/run/secrets/iotdb_auth
INTERNAL_PROXY_SECRET_FILE=/run/secrets/internal_proxy_secret
AUDIT_HMAC_SECRET_FILE=/run/secrets/audit_hmac_secret
```

Recommended control settings:

```env
NODE_ENV=production
RPC_ACL_ENABLED=true
RPC_ALLOWED_METHODS=writeTag
RPC_ALLOWED_TAGS=pump.speed,pump.enabled
RPC_REQUIRE_AUDIT=false
IOTDB_QUERY_ENABLED=false
```

`RPC_REQUIRE_AUDIT=true` is stricter: allowed RPC calls are denied if the audit log cannot be written. Use it where traceability is more important than availability.

## RPC Parameter Rules

Use `RPC_METHOD_PARAM_RULES` to constrain RPC payloads beyond the method name:

```env
RPC_METHOD_PARAM_RULES={"writeTag":{"required":["tag","value"],"allowedKeys":["tag","value"],"types":{"tag":"string","value":"number"},"ranges":{"value":{"min":0,"max":100}}}}
```

Rules support:

- `required`: params that must exist
- `allowedKeys`: params that may exist
- `types`: expected JavaScript scalar type: `string`, `number`, or `boolean`
- `ranges`: numeric `min`/`max`

## Network Controls

- Bind/expose the proxy only on the local control/HMI network.
- Do not expose port `8787` to the internet.
- Place it behind a local reverse proxy or firewall where practical.
- Restrict access to HMI/frontend hosts and engineering workstations.
- Keep ThingsBoard and IoTDB reachable only from trusted network zones.

## Container Controls

The Dockerfile runs as the non-root `node` user. Recommended runtime settings:

```bash
docker run \
  --read-only \
  --tmpfs /tmp \
  --mount type=volume,src=iotdbproxy-data,dst=/app/data \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file .env \
  -p 8787:8787 \
  iotdbproxy
```

If using Docker Compose, mount secrets under `/run/secrets/*` and keep `.env` limited to non-secret configuration and secret file paths.

## Operational Checks

Use:

```text
GET /health
```

for basic liveness.

Use:

```text
GET /twynix/status
```

with a tenant-admin user token for protected diagnostics:

- ThingsBoard admin login state
- IoTDB config state
- RPC ACL state
- audit HMAC state
- shelving DB state
- security event counters

Use:

```text
GET /twynix/metrics
```

with a tenant-admin user token for lightweight Prometheus-style counters:

- proxy uptime
- HTTP request totals
- HTTP status-class totals
- security event totals

Production guardrails:

- `AUDIT_HMAC_SECRET` is required when `NODE_ENV=production`.
- `RPC_ACL_ENABLED=false` is rejected when `NODE_ENV=production`.
- URL and positive integer config values are validated before startup.

## Pen-Test Talking Points

- The proxy does not replace ThingsBoard authentication.
- User JWTs are validated with ThingsBoard before protected operations.
- Tenant-admin credentials are used only server-side to read hidden server attributes.
- Inbound internal/trust headers are stripped before routing and proxying.
- RPC calls require device `SERVER_SCOPE.security.permissions.control`.
- RPC method, tags, params, timeout, and rate are constrained.
- Dangerous telemetry writes are intercepted.
- Security decisions are audit logged.
