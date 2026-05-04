# aspavi-auth-lib

Spring Boot auto-configuration for multi-tenant JWT authentication with Keycloak and PostgreSQL Row-Level Security.

## What it provides

| Bean | Description |
|------|-------------|
| `JwtDecoder` | Multi-tenant decoder that selects the right Keycloak realm based on the `iss` claim |
| `JwtAuthenticationConverter` | Extracts `realm_access.roles` from the JWT and maps them as-is (no `ROLE_` prefix) |
| `TenantFilter` | `OncePerRequestFilter` that reads the `tenant_id` JWT claim and stores it in `TenantContext` |
| `TenantAwareJpaTransactionManager` | `JpaTransactionManager` subclass that executes `SET LOCAL app.current_tenant` at transaction start, enabling PostgreSQL RLS |

All beans are `@ConditionalOnMissingBean` — declare your own to override any of them.

---

## Adding to a new service

### 1. Add the dependency

In `pom.xml`, add the repository and the dependency:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/aspavi/aspavi-auth-lib</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.aspavi</groupId>
        <artifactId>aspavi-auth-lib</artifactId>
        <version>1.0.0-SNAPSHOT</version>
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

### 5. Protect methods with roles

Roles arrive from Keycloak's `realm_access.roles` claim, mapped as-is (e.g. `hr_admin`, `employee_read`). Use `@PreAuthorize` directly:

```java
@PreAuthorize("hasAuthority('hr_admin')")
public void deleteEmployee(UUID id) { ... }
```

### 6. Set up PostgreSQL RLS (optional but recommended)

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

### 7. Mock `JwtDecoder` in tests

The lib registers a real `JwtDecoder` that calls Keycloak on startup. In `@SpringBootTest` tests, mock it out:

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
