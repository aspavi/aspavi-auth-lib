package com.aspavi.auth.tenant;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Knows which token issuers ({@code iss}) belong to which tenant.
 *
 * <p>Two sources, which can be combined:
 * <ul>
 *   <li>a fixed map tenant → issuer ({@code aspavi.auth.tenants}), matched exactly;</li>
 *   <li>an issuer pattern with a {@value #PLACEHOLDER} placeholder
 *       ({@code aspavi.auth.issuer-pattern}, e.g.
 *       {@code https://keycloak.aspavi.com/realms/rrhh-tenant-{tenant}}), so that a new
 *       tenant needs no configuration change. The placeholder only matches a valid tenant id
 *       ({@value #TENANT_ID_REGEX}); the rest of the pattern is matched literally.</li>
 * </ul>
 * The map is checked first.
 */
public final class TenantIssuers {

    /** A tenant id: lowercase letter first, then lowercase letters, digits or {@code -}; 2 to 30 characters. */
    public static final String TENANT_ID_REGEX = "^[a-z][a-z0-9-]{1,29}$";

    /** The placeholder of {@code aspavi.auth.issuer-pattern}. */
    public static final String PLACEHOLDER = "{tenant}";

    /** Realm name prefix of the tenant realms in Keycloak. */
    public static final String REALM_PREFIX = "rrhh-tenant-";

    private static final Pattern TENANT_ID = Pattern.compile(TENANT_ID_REGEX);
    private static final String TENANT_GROUP = "([a-z][a-z0-9-]{1,29})";
    private static final Pattern REALM_CONVENTION =
            Pattern.compile("^.+/realms/" + Pattern.quote(REALM_PREFIX) + TENANT_GROUP + "$");

    private final Map<String, String> issuerToTenant;
    private final String issuerPattern;
    private final Pattern compiledPattern;

    private TenantIssuers(Map<String, String> tenantToIssuer, String issuerPattern) {
        Map<String, String> reverse = new HashMap<>();
        tenantToIssuer.forEach((tenant, issuer) -> reverse.put(issuer, tenant));
        this.issuerToTenant = Map.copyOf(reverse);
        this.issuerPattern = issuerPattern;
        this.compiledPattern = issuerPattern == null ? null : compile(issuerPattern);
    }

    /**
     * @param tenantToIssuer fixed tenant → issuer map; may be empty
     * @param issuerPattern  issuer pattern with exactly one {@value #PLACEHOLDER}; {@code null} or blank for none
     * @throws IllegalArgumentException if the pattern does not have exactly one placeholder
     */
    public static TenantIssuers of(Map<String, String> tenantToIssuer, String issuerPattern) {
        Objects.requireNonNull(tenantToIssuer, "tenantToIssuer");
        String pattern = issuerPattern == null || issuerPattern.isBlank() ? null : issuerPattern.trim();
        return new TenantIssuers(tenantToIssuer, pattern);
    }

    /** No configured issuer: only {@link #tenantFromRealmName(String)} can name a tenant. */
    public static TenantIssuers none() {
        return new TenantIssuers(Map.of(), null);
    }

    /**
     * The tenant of a configured issuer: from the map, or from the pattern.
     * Empty when the issuer is {@code null} or matches neither.
     */
    public Optional<String> tenantFor(String issuer) {
        if (issuer == null) {
            return Optional.empty();
        }
        String fromMap = issuerToTenant.get(issuer);
        if (fromMap != null) {
            return Optional.of(fromMap);
        }
        if (compiledPattern != null) {
            Matcher matcher = compiledPattern.matcher(issuer);
            if (matcher.matches()) {
                return Optional.of(matcher.group(1));
            }
        }
        return Optional.empty();
    }

    /** The issuer pattern, or {@code null} if none is configured. */
    public String issuerPattern() {
        return issuerPattern;
    }

    /** Whether {@code tenantId} is a valid tenant id ({@value #TENANT_ID_REGEX}). */
    public static boolean isValidTenantId(String tenantId) {
        return tenantId != null && TENANT_ID.matcher(tenantId).matches();
    }

    /**
     * The tenant named by the realm of an issuer that follows the Keycloak convention
     * {@code <any base>/realms/rrhh-tenant-<tenant>}, whatever its host. It does not say the
     * issuer is trusted: that is the job of the {@code JwtDecoder}, which only accepts
     * configured issuers.
     */
    public static Optional<String> tenantFromRealmName(String issuer) {
        if (issuer == null) {
            return Optional.empty();
        }
        Matcher matcher = REALM_CONVENTION.matcher(issuer);
        return matcher.matches() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    private static Pattern compile(String issuerPattern) {
        int first = issuerPattern.indexOf(PLACEHOLDER);
        if (first < 0 || first != issuerPattern.lastIndexOf(PLACEHOLDER)) {
            throw new IllegalArgumentException(
                    "aspavi.auth.issuer-pattern must contain " + PLACEHOLDER + " exactly once: " + issuerPattern);
        }
        String prefix = issuerPattern.substring(0, first);
        String suffix = issuerPattern.substring(first + PLACEHOLDER.length());
        return Pattern.compile("^" + Pattern.quote(prefix) + TENANT_GROUP + Pattern.quote(suffix) + "$");
    }
}
