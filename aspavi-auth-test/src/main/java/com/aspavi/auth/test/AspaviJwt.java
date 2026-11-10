package com.aspavi.auth.test;

import com.aspavi.auth.security.AspaviClaims;
import com.aspavi.auth.security.KeycloakRealmRoleConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Builds a Keycloak-like JWT for tests and authenticates with it the same way
 * aspavi-auth-lib does in production: authorities come from {@code realm_access.roles}
 * through {@link KeycloakRealmRoleConverter}, with no prefix. Spring Security's bare
 * {@code jwt()} grants {@code SCOPE_read} instead, so {@code hasAuthority('employee:read')}
 * would reject it.
 *
 * <pre>{@code
 * mockMvc.perform(get("/api/v1/employees")
 *         .with(AspaviJwt.withPermissions("employee:read")))
 *     .andExpect(status().isOk());
 *
 * mockMvc.perform(get("/api/v1/me/absences")
 *         .with(AspaviJwt.withPermissions("absence:read").employeeId(employeeId)))
 *     .andExpect(status().isOk());
 * }</pre>
 *
 * <p>Defaults: tenant {@value #DEFAULT_TENANT_ID}, subject {@value #DEFAULT_SUBJECT}, no
 * {@code employee_id}. Use {@link #toAuthentication()} or {@link #authenticate()} outside
 * MockMvc (e.g. to test a service that calls {@code CurrentUser}).
 */
public final class AspaviJwt implements RequestPostProcessor {

    public static final String DEFAULT_TENANT_ID = "test";
    public static final String DEFAULT_SUBJECT = "test-user";
    public static final String DEFAULT_ISSUER = "https://keycloak.test/realms/rrhh-tenant-test";

    private final List<String> permissions;
    private String tenantId = DEFAULT_TENANT_ID;
    private String subject = DEFAULT_SUBJECT;
    private UUID employeeId;
    private final Map<String, Object> extraClaims = new LinkedHashMap<>();

    private AspaviJwt(List<String> permissions) {
        this.permissions = permissions;
    }

    /**
     * A token whose {@code realm_access.roles} holds exactly these permissions
     * (e.g. {@code "employee:read"}). Composite roles may be passed too; Keycloak would
     * send them alongside their atomic permissions. No arguments means no permissions.
     */
    public static AspaviJwt withPermissions(String... permissions) {
        Objects.requireNonNull(permissions, "permissions");
        return new AspaviJwt(new ArrayList<>(Arrays.asList(permissions)));
    }

    /** Sets the {@code tenant_id} claim (default {@value #DEFAULT_TENANT_ID}). */
    public AspaviJwt tenantId(String tenantId) {
        this.tenantId = Objects.requireNonNull(tenantId, "tenantId");
        return this;
    }

    /** Sets the {@code sub} claim, the Keycloak user id (default {@value #DEFAULT_SUBJECT}). */
    public AspaviJwt subject(String subject) {
        this.subject = Objects.requireNonNull(subject, "subject");
        return this;
    }

    /** Sets the {@code employee_id} claim; without it the token has no employee. */
    public AspaviJwt employeeId(UUID employeeId) {
        this.employeeId = Objects.requireNonNull(employeeId, "employeeId");
        return this;
    }

    /** Adds or overrides any other claim. */
    public AspaviJwt claim(String name, Object value) {
        extraClaims.put(Objects.requireNonNull(name, "name"), value);
        return this;
    }

    /** The JWT these settings describe. */
    public Jwt toJwt() {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue("aspavi-test-token")
                .header("alg", "none")
                .issuer(DEFAULT_ISSUER)
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim(AspaviClaims.TENANT_ID, tenantId)
                .claim(AspaviClaims.REALM_ACCESS, Map.of(AspaviClaims.ROLES, List.copyOf(permissions)));
        if (employeeId != null) {
            builder.claim(AspaviClaims.EMPLOYEE_ID, employeeId.toString());
        }
        builder.claims(claims -> claims.putAll(extraClaims));
        return builder.build();
    }

    /** An authenticated token with the authorities the production converter would grant. */
    public JwtAuthenticationToken toAuthentication() {
        Jwt jwt = toJwt();
        return new JwtAuthenticationToken(jwt, new KeycloakRealmRoleConverter().convert(jwt), jwt.getSubject());
    }

    /**
     * Puts {@link #toAuthentication()} in the {@link SecurityContextHolder} of the current
     * thread, for tests that call services directly. Clear it afterwards with
     * {@code SecurityContextHolder.clearContext()}.
     */
    public void authenticate() {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(toAuthentication());
        SecurityContextHolder.setContext(context);
    }

    /** MockMvc: authenticates the request with this token. */
    @Override
    public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
        return SecurityMockMvcRequestPostProcessors.jwt()
                .jwt(toJwt())
                .authorities(new KeycloakRealmRoleConverter())
                .postProcessRequest(request);
    }
}
