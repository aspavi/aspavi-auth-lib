# aspavi-auth-lib

Spring Boot auto-configuration for multi-tenant JWT authentication with Keycloak and PostgreSQL Row-Level Security.

The repository builds two artifacts:

| Artifact | Scope in a service | Contents |
|----------|--------------------|----------|
| `com.aspavi:aspavi-auth-lib` | compile | Auto-configuration, `CurrentUser`, `TenantContext`, `TenantFilter` |
| `com.aspavi:aspavi-auth-test` | test | `AspaviJwt`, to authenticate MockMvc requests and tests like production does |

Both are published together with their parent POM (`com.aspavi:aspavi-auth-parent`) under the same version.

## What it provides

| Bean / class | Description |
|--------------|-------------|
| `JwtDecoder` | Multi-tenant decoder that selects the right Keycloak realm based on the `iss` claim |
| `JwtAuthenticationConverter` | Maps `realm_access.roles` to authorities as-is (no `ROLE_`/`SCOPE_` prefix) through `KeycloakRealmRoleConverter`. Null-safe; ignores non-string entries |
| `TenantFilter` | `OncePerRequestFilter` that reads the `tenant_id` JWT claim and stores it in `TenantContext` |
| `TenantAwareJpaTransactionManager` | `JpaTransactionManager` subclass that executes `SET LOCAL app.current_tenant` at transaction start, enabling PostgreSQL RLS |
| `CurrentUser` | Static access to the current user: `userId()`, `tenantId()`, `employeeId()`, `requireEmployeeId()`, `hasPermission(...)` |
| `AspaviClaims` | Claim names: `tenant_id`, `employee_id`, `realm_access`, `roles` |

All beans are `@ConditionalOnMissingBean` (except the transaction manager) — declare your own to override any of them.

---

## Adding to a service

### 1. Add the dependencies

In `pom.xml`, add the repository and the dependencies. Always use a fixed release version, never a `-SNAPSHOT`:

```xml
<properties>
    <aspavi-auth.version>1.1.0</aspavi-auth.version>
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

    <!-- The lib's security/JPA deps are optional — bring them explicitly -->
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

```yaml
aspavi:
  auth:
    tenants:
      acme: ${KEYCLOAK_BASE_URL:https://keycloak.aspavi.com}/realms/rrhh-tenant-acme
      test: ${KEYCLOAK_BASE_URL:https://keycloak.aspavi.com}/realms/rrhh-tenant-test
```

Each key is the `tenant_id` claim value that Keycloak includes in the JWT. The value is the issuer URI used for OIDC discovery. Add new tenants here and redeploy — no code changes needed.

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

Spring Security's bare `jwt()` grants `SCOPE_read`, so `hasAuthority('employee:read')` answers 403. `AspaviJwt` (from `aspavi-auth-test`) builds a Keycloak-like token (`tenant_id`, `sub`, optional `employee_id`, `realm_access.roles`) and grants the authorities exactly as the production converter does:

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
| `AspaviJwt tenantId(String)` | `tenant_id` claim (default `test`) |
| `AspaviJwt subject(String)` | `sub` claim (default `test-user`) |
| `AspaviJwt employeeId(UUID)` | `employee_id` claim (absent by default) |
| `AspaviJwt claim(String, Object)` | Any other claim |
| `Jwt toJwt()` | The token |
| `JwtAuthenticationToken toAuthentication()` | Authenticated token with production authorities |
| `void authenticate()` | Puts `toAuthentication()` in `SecurityContextHolder` (clear it in `@AfterEach`) |

`AspaviJwt` is a MockMvc `RequestPostProcessor`; it goes through the security filter chain, so `TenantFilter` fills `TenantContext` as in production.

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
