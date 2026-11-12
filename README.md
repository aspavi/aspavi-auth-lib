# aspavi-auth-lib

Spring Boot auto-configuration for multi-tenant JWT authentication with Keycloak and PostgreSQL Row-Level Security.

The repository builds two artifacts:

| Artifact | Scope in a service | Contents |
|----------|--------------------|----------|
| `com.aspavi:aspavi-auth-lib` | compile | Auto-configuration, `CurrentUser`, `TenantContext`, `TenantIssuers`, `TenantFilter` |
| `com.aspavi:aspavi-auth-test` | test | `AspaviJwt`, to authenticate MockMvc requests and tests like production does |

Both are published together with their parent POM (`com.aspavi:aspavi-auth-parent`) under the same version.

## What it provides

| Bean / class | Description |
|--------------|-------------|
| `TenantIssuers` | Which issuers belong to which tenant: the `aspavi.auth.tenants` map and/or the `aspavi.auth.issuer-pattern` |
| `JwtDecoder` | Multi-tenant decoder: accepts only the issuers of `TenantIssuers`, discovers each realm's keys on first use and caches them (bounded, with a negative cache for realms that do not exist) |
| `JwtAuthenticationConverter` | Maps `realm_access.roles` to authorities as-is (no `ROLE_`/`SCOPE_` prefix) through `KeycloakRealmRoleConverter`. Null-safe; ignores non-string entries |
| `TenantFilter` | `OncePerRequestFilter` that takes the tenant from the realm that issued the JWT, requires the `tenant_id` claim to be equal, and stores it in `TenantContext`; otherwise 401 |
| `TenantAwareJpaTransactionManager` | `JpaTransactionManager` subclass that executes `SET LOCAL app.current_tenant` at transaction start, enabling PostgreSQL RLS. Only when JPA is on the classpath and there is an `EntityManagerFactory` |
| `CurrentUser` | Static access to the current user: `userId()`, `tenantId()`, `employeeId()`, `requireEmployeeId()`, `hasPermission(...)` |
| `AspaviClaims` | Claim names: `tenant_id`, `employee_id`, `realm_access`, `roles` |

All beans are `@ConditionalOnMissingBean` (except the transaction manager) — declare your own to override any of them.

---

## Adding to a service

### 1. Add the dependencies

In `pom.xml`, add the repository and the dependencies. Always use a fixed release version, never a `-SNAPSHOT`:

```xml
<properties>
    <aspavi-auth.version>1.2.0</aspavi-auth.version>
</properties>

<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/aspavi/aspavi-auth-lib</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.aspavi</groupId>
        <artifactId>aspavi-auth-lib</artifactId>
        <version>${aspavi-auth.version}</version>
    </dependency>

    <!-- The lib's security/JPA deps are optional — bring them explicitly.
         A service without a database (e.g. iam-service) can leave JPA out (1.1.1+). -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>

    <!-- Test support -->
    <dependency>
        <groupId>com.aspavi</groupId>
        <artifactId>aspavi-auth-test</artifactId>
        <version>${aspavi-auth.version}</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

The GitHub Packages repository requires authentication. In CI, the `setup-java` action with `server-id: github` and a `PACKAGES_TOKEN` env var handles this automatically (see the existing service workflows for the pattern).

### 2. Configure tenants in `application.yml`

There are two ways, and they can be combined.

**Issuer pattern (since 1.2.0)** — a new tenant needs no change, no redeploy and no restart of the service:

```yaml
aspavi:
  auth:
    issuer-pattern: ${KEYCLOAK_BASE_URL:https://keycloak.aspavi.com}/realms/rrhh-tenant-{tenant}
```

Any issuer that matches the pattern is accepted, with `{tenant}` a valid tenant id: `^[a-z][a-z0-9-]{1,29}$` (lowercase letter first, 2–30 characters). The rest of the pattern is matched literally. The pattern must contain `{tenant}` exactly once, or the service does not start.

**Fixed map** — each tenant listed with its issuer; still valid for the `local` profile, the local environment and tests:

```yaml
aspavi:
  auth:
    tenants:
      acme: http://localhost:8180/realms/rrhh-tenant-acme
      test: http://localhost:8180/realms/rrhh-tenant-test
```

Each key is the tenant id; the value is its issuer. A token's `iss` must equal a value exactly.

With both, an issuer is accepted if it is in the map or matches the pattern (the map is checked first). See [Issuers and the local environment](#issuers-and-the-local-environment) for how issuers are validated.

Optional cache settings (defaults shown):

```yaml
aspavi:
  auth:
    issuer-cache:
      max-size: 100            # decoders kept (one per issuer); the least recently used goes first
      unknown-issuer-ttl: 5m   # how long a realm that does not exist is rejected without asking Keycloak again
```

### 3. Write a `SecurityConfig`

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtDecoder jwtDecoder;
    private final TenantFilter tenantFilter;

    public SecurityConfig(JwtDecoder jwtDecoder, TenantFilter tenantFilter) {
        this.jwtDecoder = jwtDecoder;
        this.tenantFilter = tenantFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/actuator/health/**", "/v3/api-docs/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder))
            )
            .addFilterAfter(tenantFilter, BearerTokenAuthenticationFilter.class);

        return http.build();
    }
}
```

There is no need to pass the `JwtAuthenticationConverter` to `.jwt(...)`: Spring Security takes the lib's bean from the context. Passing it explicitly (`.jwtAuthenticationConverter(converter)`) is equivalent. Do not declare a second `JwtAuthenticationConverter` bean, and do not set `spring.security.oauth2.resourceserver.jwt.authorities-claim-name` / `authority-prefix`.

### 4. Use `TenantContext` in the service layer

```java
import com.aspavi.auth.tenant.TenantContext;

@Service
public class MyService {

    @Transactional
    public MyEntity create(MyRequest request) {
        String tenantId = TenantContext.getRequiredTenantId(); // throws if not set
        // ...
    }
}
```

`TenantContext.getTenantId()` returns `null` if no tenant is set (unauthenticated paths).
`TenantContext.getRequiredTenantId()` throws `IllegalStateException` — use in methods that must have a tenant.

### 5. Protect endpoints with permissions

Permissions are atomic Keycloak realm roles named `<resource>:read` / `<resource>:write` (e.g. `employee:read`). Roles are composite realm roles that group permissions; Keycloak puts the user's effective roles in `realm_access.roles`, so a token carries every atomic permission of its composite roles. Services only check permissions, never composite roles:

```java
@GetMapping("/api/v1/employees/{id}")
@PreAuthorize("hasAuthority('employee:read')")
public EmployeeResponse get(@PathVariable UUID id) { ... }

@PutMapping("/api/v1/employees/{id}")
@PreAuthorize("hasAuthority('employee:write')")
public EmployeeResponse update(@PathVariable UUID id, @RequestBody EmployeeRequest request) { ... }
```

Each service keeps the constants for its own permissions; the lib does not define them. A permission change in Keycloak reaches a user when their token is refreshed.

Spring Security 7 adds its own `FACTOR_BEARER` authority to every bearer-token authentication, next to the realm roles. It does not affect `hasAuthority(...)`, but a test that compares the exact list of authorities of a real request must expect it. `AspaviJwt` does not add it (it skips the authentication provider).

### 6. Identify the current user with `CurrentUser`

The identity of the current user always comes from the token. Never accept `employeeId`, `approverId` or `createdBy` for the current user from a request body; self-service endpoints live under `/api/v1/me/...`:

```java
import com.aspavi.auth.security.CurrentUser;

@GetMapping("/api/v1/me/absences")
public List<AbsenceResponse> myAbsences() {
    return absenceService.findByEmployee(CurrentUser.requireEmployeeId());
}
```

| Method | Returns | Fails with |
|--------|---------|------------|
| `String userId()` | Keycloak user id (`sub`) | |
| `String tenantId()` | `tenant_id` claim | |
| `Optional<UUID> employeeId()` | `employee_id` claim, empty when absent | `IdentityClaimException` if it is not a UUID |
| `UUID requireEmployeeId()` | `employee_id` claim | `IdentityClaimException` if absent or not a UUID |
| `boolean hasPermission(String)` | whether the user has that authority; `false` without an authenticated user | — |

All methods except `hasPermission` throw `AuthenticationCredentialsNotFoundException` (401) when there is no JWT-authenticated user, and `IdentityClaimException` when a required claim is missing.

`IdentityClaimException` extends Spring Security's `AccessDeniedException`, so the response is `403 Forbidden` without extra code. If your service has a catch-all `@ExceptionHandler(Exception.class)`, map `AccessDeniedException` to 403 before it:

```java
@ExceptionHandler(AccessDeniedException.class)
ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse("FORBIDDEN", ex.getMessage()));
}
```

The `employee_id` claim comes from a Keycloak user attribute mapper.

### 7. Set up PostgreSQL RLS (optional but recommended)

`TenantAwareJpaTransactionManager` sets `SET LOCAL app.current_tenant = '<tenantId>'` on the transaction connection. Wire up RLS policies in your migration:

```sql
-- Enable RLS on the table
ALTER TABLE my_table ENABLE ROW LEVEL SECURITY;

-- Allow app_user to see only its own tenant's rows
CREATE POLICY tenant_isolation ON my_table
    USING (tenant_id = current_setting('app.current_tenant', true));

-- app_user needs BYPASSRLS disabled (default) and the policy must apply
ALTER TABLE my_table FORCE ROW LEVEL SECURITY;
```

> Before 1.1.0 the transaction manager was not registered on Spring Boot 4 (the auto-configuration ordering pointed at the Boot 3 class name), so `app.current_tenant` was never set. From 1.1.0 it is active.

### 8. Tests

#### MockMvc with permissions — `AspaviJwt`

Spring Security's bare `jwt()` grants `SCOPE_read`, so `hasAuthority('employee:read')` answers 403; since 1.2.0 it gets 401 first, because it has no issuer or `tenant_id` naming a tenant. `AspaviJwt` (from `aspavi-auth-test`) builds a Keycloak-like token (`tenant_id`, `sub`, optional `employee_id`, `realm_access.roles`) and grants the authorities exactly as the production converter does:

```java
import static com.aspavi.auth.test.AspaviJwt.withPermissions;

mockMvc.perform(get("/api/v1/employees").with(withPermissions("employee:read")))
       .andExpect(status().isOk());

mockMvc.perform(get("/api/v1/employees").with(withPermissions("employee:write")))
       .andExpect(status().isForbidden());

mockMvc.perform(get("/api/v1/me/absences")
               .with(withPermissions("absence:read").tenantId("acme").employeeId(employeeId)))
       .andExpect(status().isOk());
```

| Method | Description |
|--------|-------------|
| `static AspaviJwt withPermissions(String... permissions)` | Token whose `realm_access.roles` holds these permissions (none if empty) |
| `AspaviJwt tenantId(String)` | `tenant_id` claim (default `test`); the issuer follows it: `https://keycloak.test/realms/rrhh-tenant-<tenant>` |
| `AspaviJwt issuer(String)` | `iss` claim, if it must not follow the tenant (e.g. to test a token whose `tenant_id` does not match its realm) |
| `static String issuerFor(String tenantId)` | The default issuer of a test token of that tenant |
| `AspaviJwt subject(String)` | `sub` claim (default `test-user`) |
| `AspaviJwt employeeId(UUID)` | `employee_id` claim (absent by default) |
| `AspaviJwt claim(String, Object)` | Any other claim |
| `Jwt toJwt()` | The token |
| `JwtAuthenticationToken toAuthentication()` | Authenticated token with production authorities |
| `void authenticate()` | Puts `toAuthentication()` in `SecurityContextHolder` (clear it in `@AfterEach`) |

`AspaviJwt` is a MockMvc `RequestPostProcessor`; it goes through the security filter chain, so `TenantFilter` fills `TenantContext` as in production. Its issuer and its `tenant_id` always name the same tenant unless `issuer(...)` or `claim("tenant_id", ...)` is used, so it needs no tenant configuration in the test `application.yml`.

#### Service-layer tests that use `CurrentUser`

```java
@BeforeEach
void authenticate() {
    AspaviJwt.withPermissions("absence:write").tenantId("acme").employeeId(EMPLOYEE_ID).authenticate();
}

@AfterEach
void clear() {
    SecurityContextHolder.clearContext();
}
```

#### Mock `JwtDecoder`

The lib registers a real `JwtDecoder` that calls Keycloak on first use. In `@SpringBootTest` tests, mock it out:

```java
@SpringBootTest
class MyServiceApplicationTests {

    @MockitoBean
    JwtDecoder jwtDecoder;

    @Test
    void contextLoads() {}
}
```

A `Jwt` that such a mock returns must name its tenant twice, like a real one: an `iss` of the tenant's realm (in the map, matching the pattern, or ending in `/realms/rrhh-tenant-<tenant>`) and the same `tenant_id`. `AspaviJwt.withPermissions(...).tenantId("acme").toJwt()` does both.

For unit tests that call service methods which use `TenantContext`, set the tenant manually:

```java
@BeforeEach
void setTenant() {
    TenantContext.setTenantId("acme");
}

@AfterEach
void clearTenant() {
    TenantContext.clear();
}
```

---

## Issuers and the local environment

### How the issuer is validated

- `MultiTenantJwtDecoder` reads `iss` from the token **without** verifying it, only to choose a decoder. An `iss` that is neither in `aspavi.auth.tenants` (exact match: scheme, host, port and path) nor matches `aspavi.auth.issuer-pattern` gets 401 (`Unknown or missing issuer in token`) **without any request to Keycloak**.
- For an accepted issuer, on its first token the decoder calls `<issuer>/.well-known/openid-configuration` once, checks that the `issuer` in that document equals the token's, and builds a decoder on the `jwks_uri` it returns. That decoder verifies the signature with that realm's keys and requires `iss` to equal the issuer. A token of realm A signed with the keys of realm B is rejected.
- Decoders are cached per issuer, up to `issuer-cache.max-size` (least recently used out first).
- If discovery answers 404/410 (Keycloak's answer for a realm that does not exist), or the document describes another issuer, the issuer is rejected for `issuer-cache.unknown-issuer-ttl` without asking Keycloak again, so a made-up `iss` that fits the pattern does not reach Keycloak on every request. A tenant whose realm is created meanwhile is accepted once that time has passed. Other failures (Keycloak unreachable, timeout, 5xx) are not remembered, and the next request tries again.
- So the issuer must be the exact `iss` of the tokens **and** reachable, together with its `jwks_uri`, from wherever the service runs. Listing several issuers per tenant would not change this: the discovery URL and the keys URL come from the issuer.

### How the tenant of a request is decided

`TenantFilter` runs after the token has been validated:

- the tenant is the one of the realm that issued the token: its tenant in the map, or the `{tenant}` of the pattern. For an issuer the library's decoder did not check (test tokens, or a service with its own `JwtDecoder`), it falls back to the realm name `.../realms/rrhh-tenant-<tenant>`;
- the `tenant_id` claim must be present and equal to it. Every real token has it (a Keycloak mapper sets it for users and for service accounts);
- otherwise the request ends with **401** and the common error body, before any controller runs:

```json
{"timestamp":"2026-11-12T10:15:30.123","status":401,"error":"UNAUTHORIZED",
 "message":"Token tenant_id does not match the realm that issued it","path":"/api/v1/employees"}
```

Messages: `Token issuer does not belong to any tenant`, `Token has no tenant_id claim`, `Token tenant_id does not match the realm that issued it`. Before 1.2.0 a token without `tenant_id` went through without a tenant, and the claim was not compared with the realm.

Requests without a JWT (public endpoints) go through without a tenant, as before.

### aspavi-local (the local Docker environment)

- Keycloak runs with `KC_HOSTNAME=http://keycloak:8080`. Every token, and every URL in its discovery document (`issuer`, `jwks_uri`, `token_endpoint`), uses `http://keycloak:8080`, even when it is requested through the published port `localhost:8180`.
- The services run inside the Docker network with the `aspavi` profile and `KEYCLOAK_BASE_URL=http://keycloak:8080`, so `${KEYCLOAK_BASE_URL}/realms/rrhh-tenant-<x>` matches the tokens and resolves. This works.
- A service started on the host with the `local` profile does **not** work against aspavi-local: its issuer is `http://localhost:8180/...`, the tokens say `http://keycloak:8080/...`, and `keycloak` does not resolve on the host.

### The `local` profile (`localhost:8180`)

The `http://localhost:8180/realms/rrhh-tenant-<x>` issuers in `application.yml` and `application-local.yml` only match the Keycloak of the service's own `docker-compose.yml` (employee-service and organization-service have one). That Keycloak listens on 8180 without `KC_HOSTNAME`, so the tokens it issues on the host say `http://localhost:8180/...`.

### Testing a new jar against aspavi-local

Run the service in its container and mount the new jar with a compose override kept **outside** the aspavi-local compose. The network, the `keycloak` alias, the environment variables and the port come from the base compose; only the jar changes. Example from `local-overrides/employee/` in the workspace root:

```yaml
# local-overrides/employee/docker-compose.override.yml
services:
  employee:
    volumes: !override
      - <workspace>/local-overrides/employee/employee.jar:/app/app.jar:ro
```

```bash
ASPAVI_ROOT=<workspace> docker compose -p aspavi-local \
  -f <workspace>/aspavi-harness/entorno-local/docker-compose.yml \
  -f <workspace>/local-overrides/employee/docker-compose.override.yml \
  up -d --no-deps --force-recreate employee
```

`--no-deps` leaves the other containers alone. Do not recreate the `keycloak` container: it runs `start-dev` without a data volume, so a new container goes back to the imported realms and loses the roles and assignments made since.

### Possible improvement: debugging from the IDE against aspavi-local

Not implemented. A backward-compatible option (a later minor version) is an optional `aspavi.auth.jwk-set-uris.<tenant>`. For a tenant that sets it, the decoder would skip discovery, fetch the keys from that URI and still require the exact `iss` of `aspavi.auth.tenants` or of the pattern:

```yaml
aspavi:
  auth:
    tenants:
      test: http://keycloak:8080/realms/rrhh-tenant-test
    jwk-set-uris:
      test: http://localhost:8180/realms/rrhh-tenant-test/protocol/openid-connect/certs
```

Services would need to move to that version and change their `application-local.yml`; iam-service would also need `KEYCLOAK_ADMIN_BASE_URL=http://localhost:8180`.

---

## Versioning and releases

| Event | What CI does |
|-------|--------------|
| Pull request | `mvn verify` |
| Push to `master` with a `-SNAPSHOT` version | `mvn deploy` of the snapshot |
| Push to `master` with a release version | `mvn verify` only |
| Push of tag `vX.Y.Z` | Checks the tag matches the pom version, then `mvn deploy` of release `X.Y.Z` |

To release `X.Y.Z`:

1. In a PR, set the version of the three POMs to `X.Y.Z` (`mvn versions:set -DnewVersion=X.Y.Z -DgenerateBackupPoms=false`) and merge it.
2. Tag the merge commit `vX.Y.Z` and push the tag; the workflow publishes the release.
3. Move `master` to the next snapshot (`X.(Y+1).0-SNAPSHOT`).

Release versions are immutable in GitHub Packages. Services must depend on a release version, never on a snapshot.

`1.0.0-SNAPSHOT` is the pre-1.1.0 version, kept in GitHub Packages for services that have not moved to a release yet. Do not republish it.
