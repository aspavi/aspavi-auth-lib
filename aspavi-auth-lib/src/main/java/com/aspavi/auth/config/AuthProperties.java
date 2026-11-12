package com.aspavi.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Configuration properties for the Aspavi Auth library.
 *
 * <p>Bind in {@code application.yml} under the {@code aspavi.auth} prefix. Either a pattern,
 * so that a new tenant needs no configuration change:
 *
 * <pre>
 * aspavi:
 *   auth:
 *     issuer-pattern: ${KEYCLOAK_BASE_URL}/realms/rrhh-tenant-{tenant}
 * </pre>
 *
 * or a fixed map, or both:
 *
 * <pre>
 * aspavi:
 *   auth:
 *     tenants:
 *       acme: https://keycloak.example.com/realms/rrhh-tenant-acme
 *       test: https://keycloak.example.com/realms/rrhh-tenant-test
 * </pre>
 */
@ConfigurationProperties(prefix = "aspavi.auth")
public class AuthProperties {

    /**
     * Map of tenant-id → Keycloak issuer URI. The {@code iss} of the token must match a value exactly.
     */
    private Map<String, String> tenants = new HashMap<>();

    /**
     * Issuer URI with a {@code {tenant}} placeholder, e.g.
     * {@code https://keycloak.aspavi.com/realms/rrhh-tenant-{tenant}}. Any issuer that matches it,
     * with a tenant id like {@code ^[a-z][a-z0-9-]{1,29}$}, is accepted; its keys are discovered
     * on first use. Works together with {@link #tenants}.
     */
    private String issuerPattern;

    private final IssuerCache issuerCache = new IssuerCache();

    public Map<String, String> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, String> tenants) {
        this.tenants = tenants;
    }

    public String getIssuerPattern() {
        return issuerPattern;
    }

    public void setIssuerPattern(String issuerPattern) {
        this.issuerPattern = issuerPattern;
    }

    public IssuerCache getIssuerCache() {
        return issuerCache;
    }

    /** Caches of the multi-tenant JWT decoder. */
    public static class IssuerCache {

        /** Maximum number of issuers whose decoder (discovery + keys) is kept; the least recently used goes first. */
        private int maxSize = 100;

        /**
         * How long an issuer whose realm does not exist (discovery answers 404) is rejected without
         * asking Keycloak again. A tenant created meanwhile is accepted once this time has passed.
         */
        private Duration unknownIssuerTtl = Duration.ofMinutes(5);

        public int getMaxSize() {
            return maxSize;
        }

        public void setMaxSize(int maxSize) {
            this.maxSize = maxSize;
        }

        public Duration getUnknownIssuerTtl() {
            return unknownIssuerTtl;
        }

        public void setUnknownIssuerTtl(Duration unknownIssuerTtl) {
            this.unknownIssuerTtl = unknownIssuerTtl;
        }
    }
}
