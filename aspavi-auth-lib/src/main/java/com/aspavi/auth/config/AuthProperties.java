package com.aspavi.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration properties for the Aspavi Auth library.
 *
 * <p>Bind in {@code application.yml} under the {@code aspavi.auth} prefix:
 *
 * <pre>
 * aspavi:
 *   auth:
 *     tenants:
 *       acme: https://keycloak.example.com/realms/acme
 *       test: https://keycloak.example.com/realms/test
 * </pre>
 */
@ConfigurationProperties(prefix = "aspavi.auth")
public class AuthProperties {

    /**
     * Map of tenant-id → Keycloak issuer URI.
     * Each entry is used to build a dedicated {@link org.springframework.security.oauth2.jwt.JwtDecoder}.
     */
    private Map<String, String> tenants = new HashMap<>();

    public Map<String, String> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, String> tenants) {
        this.tenants = tenants;
    }
}
