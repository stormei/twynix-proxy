# Incoming request flow

`app.js` starter med konfigurasjon, oppretter en delt `axios`-klient og logger inn mot ThingsBoard som admin ved oppstart. Alle innkommende requests får et `X-Request-Id`; eksisterende header videreføres, ellers genereres en UUID. Requesten går deretter gjennom CORS, global rate limiting og en enkel request-logger som redakterer auth-headere.

Før proxying kjøres flere lokale middleware-lag:

- `writePolicyMiddleware` tillater et begrenset sett management-skrivinger dersom brukeren har en rolle i `MGMT_ALLOWED_ROLES`.
- `createTelemetryWriteGuard(...)` blokkerer de fleste telemetry-skrivinger som ikke går via tillatte stier.
- `permissionCheckMiddleware` beskytter `SHARED_SCOPE`-skrivinger ved å lese `security`-attributtet på mål-entity.
- `rpcPermissionMiddleware` er aktivert som standard og beskytter RPC-ruter.

Til slutt holdes noen ruter lokale i proxyen:

- `/telemetry/*`
- `/query`
- `/health`
- `/api/access/check/*`
- `/twynix/oplog*`
- `/twynix/alarms/*`

Vanlige `GET`/`HEAD`-kall proxes videre etter at proxyen har validert brukerens JWT; ThingsBoard tar selve autorisasjonen. Skrivende kall må matche proxyens eksplisitte allowlist og relevante middleware-policyer før de proxes videre.

# Auth flow

Brukerautentisering baserer seg på `X-Authorization: Bearer <jwt>`. Proxyen verifiserer ikke signaturen lokalt; i stedet kalles ThingsBoard sitt `/api/auth/user` via `assertTokenValid(userToken)`. Resultatet caches kort i `tokenValidityCache`, begrenset av JWT-exp og maks 60 sekunder.

Etter gyldig token trekkes brukerinfo ut lokalt fra JWT:

- `getUserIdFromToken(...)` henter `userId` eller `sub`
- `getTenantIdFromToken(...)` henter `tenantId` eller `tenant_id`
- `getUserAuthoritiesFromToken(...)` leser roller/authorities for management-skrivinger

`requireValidUser(req, res)` brukes av lokale Twynix-ruter og returnerer `{ userToken, userId, tenantId }`. Samtidig settes `req.__twynixAuth`, som senere brukes av audit/oplog og write-guard-logikk.

# Admin token flow

Ved oppstart og ved behov logger proxyen inn som ThingsBoard-admin med `TB_ADMIN_USERNAME` og `TB_ADMIN_PASSWORD` mot `/api/auth/login`. Hemmeligheter kan også lastes fra filer med `_FILE`-varianten, for eksempel `TB_ADMIN_PASSWORD_FILE=/run/secrets/tb_admin_password`. Tokenet lagres i `adminToken`, og utløp leses fra JWT-payloaden og lagres i `adminTokenExpiry`.

`getAdminToken()` refresher tokenet dersom det mangler eller er mindre enn 60 sekunder fra utløp. Den delte `axios`-klienten har også en response-interceptor: dersom et kall markert med `__tbAdmin` får `401`, logges admin inn på nytt og requesten prøves én gang til.

Admin-tokenet brukes til ThingsBoard-kall som proxyen selv gjør, blant annet:

- lesing av `security`-attributter
- oppslag/opprettelse av journal-asset for oplog
- skriving av oplog-telemetri

Disse interne kallene sender også `x-twynix-internal-admin`, men innkommende klient-headere med samme navn strippes før routing og før proxying.

# TB pass-through routes

Proxyen er bygd som en "local-first" frontend foran ThingsBoard. Ruter som ikke matcher lokale endepunkter går gjennom `src/security-policy.js` før de går videre via `tbProxy`.

Det betyr i praksis:

- `POST /api/auth/login` er public pass-through
- `GET`/`HEAD` krever gyldig bruker-token og proxes til ThingsBoard, som håndhever rettigheter
- `POST`/`PUT`/`PATCH`/`DELETE` må være eksplisitt tillatt og beskyttes videre av write/RPC/telemetry-policyene

Proxyen rewrites ikke path (`pathRewrite: (path_) => path_`). RPC-bodyer parses for validering og re-streames med `fixRequestBody`; andre proxied bodyer sendes videre uten global body parsing.

# Local-only routes

Disse rutene håndteres lokalt og proxes ikke til ThingsBoard:

- `GET /health`
- `GET /api/access/check/:entityType/:entityId`
- `POST /telemetry/:deviceId`
- `POST /query` (deaktivert som standard med mindre `IOTDB_QUERY_ENABLED=true`)
- `POST /twynix/oplog/write`
- `GET /twynix/oplog`
- `POST /twynix/alarms/shelve`
- `POST /twynix/alarms/unshelve`
- `POST /twynix/alarms/shelving/lookup`

`/telemetry/:deviceId` og `/query` går videre til IoTDB, ikke ThingsBoard. Oplog- og shelving-rutene er Twynix-spesifikke og bruker lokal auth + backend-kall til ThingsBoard og SQLite.

# Write-protected routes

`createTelemetryWriteGuard(...)` innfører en smal deny-by-default-policy for telemetry-plugin-skrivinger. Den aktiveres bare for `POST|PUT|PATCH|DELETE` under `/api/plugins/telemetry/*`.

Tillatt:

- `.../SHARED_SCOPE` når `permissionCheckMiddleware` har godkjent requesten
- `.../SERVER_SCOPE` når `writePolicyMiddleware` har satt `req.__allowedMgmtWrite = true`
- interne admin-kall med korrekt `x-twynix-internal-admin`

Blokkert:

- alle andre telemetry write-kall under `/api/plugins/telemetry/*`

Ved blokkering opprettes et audit-oppslag med type `write_blocked`, og klienten får `403 Writes must use SHARED_SCOPE via proxy policy`.

# RPC-protected routes

Når `RPC_ACL_ENABLED` ikke eksplisitt er satt til `false`, beskyttes:

- `POST /api/plugins/rpc/oneway/:deviceId`
- `POST /api/plugins/rpc/twoway/:deviceId`

Flowen er:

1. Les `X-Authorization`
2. Verifiser token via `assertTokenValid(...)`
3. Hent `userId` og `tenantId`
4. Les `DEVICE`-attributtet `security` via admin-token
5. Parse JSON og sjekk om `permissions.control` inneholder brukerens `userId`

Hvis brukeren ikke har `control`, returneres `403`. Middlewareen validerer også RPC-body:

- `method` må være i `RPC_ALLOWED_METHODS`
- `timeout` for twoway-kall må være innenfor `RPC_TIMEOUT_MAX_MS`
- per bruker+device begrenses med `RPC_RATE_WINDOW_MS` og `RPC_RATE_MAX`
- hvis `RPC_ALLOWED_TAGS` er satt, må `params.tag` være i listen
- hvis `RPC_METHOD_PARAM_RULES` er satt, valideres required params, tillatte nøkler, typer og numeriske ranges
- hvis `RPC_REQUIRE_AUDIT=true`, nektes tillatte RPC-kall dersom audit ikke kan skrives

# Status endpoint

`GET /twynix/status` og `GET /twynix/metrics` er lokale, beskyttede status-endepunkter. De krever gyldig bruker-token med rolle i `MGMT_ALLOWED_ROLES`.

`/twynix/status` returnerer blant annet:

- uptime
- ThingsBoard service-login state
- IoTDB konfigurasjon/feilstatus
- RPC ACL status
- audit/HMAC status
- shelving database status
- HTTP counters
- security event counters

`/twynix/metrics` returnerer en enkel Prometheus-style tekstrespons med uptime, HTTP request counters og security event counters.

# Audit events

Audit/oplog er sentralisert i `src/twynix-oplog.js`. `createOplogEmitter(...)` bygger en kanonisk entry og skriver den som ThingsBoard-telemetri på en tenant-spesifikk journal-asset.

Typiske felter i en audit-entry:

- `type`
- `userId`
- `tenantId`
- `targetType`
- `targetId`
- `corr` fra `X-Request-Id`
- `action.method`
- `action.path`
- `result.state`
- `result.detail`

Sensitive nøkler i params redakteres (`password`, `token`, `secret`, `authorization`, `auth`), store payloads trunkeres, og `result.detail` kappes til 512 tegn.

Oplog skrives både via eksplisitte ruter:

- `POST /twynix/oplog/write`
- `GET /twynix/oplog`

og implisitt fra middleware ved hendelser som:

- `shared_write`
- `rpc_oneway` / `rpc_twoway`
- `mgmt_write`
- `write_blocked`
- `alarm_shelve`
- `alarm_unshelve`

Hvis `AUDIT_HMAC_SECRET` er satt, signeres entries med HMAC-SHA256 før lagring.

# Shelving storage

Alarm shelving lagres lokalt i SQLite via `better-sqlite3`. Standard databasefil er `./data/twynix-shelving.db`, styrt av `SHELVING_DB_PATH`.

Tabellen `alarm_shelving` har primærnøkkel:

- `tenant_id`
- `originator_id`
- `alarm_type`

Hver rad inneholder:

- `shelved_until`
- `shelved_at`
- `shelved_by`
- `reason_code`
- `comment`

Egenskaper i implementasjonen:

- shelving er tenant-isolert
- shelve/unshelve krever `permissions.control` på originator
- lookup returnerer bare originatorer der brukeren har `permissions.read` eller `permissions.control`
- `shelve` gjør upsert, så samme alarmdefinisjon kan oppdateres
- `unshelve` sletter eksakt nøkkel
- `lookup` returnerer bare ikke-utløpte shelvings
- periodisk cleanup fjerner utløpte rader med intervall `SHELVING_SWEEP_MS`
- SQLite kjøres med `WAL` og `synchronous = NORMAL`

# Open questions

- Det bør bekreftes at alle relevante JWT-er inneholder `tenantId` eller `tenant_id`.
- `permissionCheckMiddleware` og `rpcPermissionMiddleware` bruker `permissions.control` i `security`-attributtet. Formatet på dette attributtet bør dokumenteres eksplisitt utenfor koden.
- `writePolicyMiddleware` tillater `SERVER_SCOPE`-skrivinger for admins, mens telemetry-guard ellers nekter writes. Det bør avklares om dette er hele ønsket management-surface eller bare et første steg.
- `/api/access/check/:entityType/:entityId` er lokal, men merket som "unchanged logic". Det er uklart om den er ment som intern hjelpe-API eller offentlig frontend-endepunkt.
- Oplog lagres i ThingsBoard-telemetri på en asset per tenant. Det bør bekreftes om retention, søkbarhet og eksportbehov er dekket av denne modellen.
- Produksjon krever `AUDIT_HMAC_SECRET`; uten den stopper prosessen ved oppstart.
