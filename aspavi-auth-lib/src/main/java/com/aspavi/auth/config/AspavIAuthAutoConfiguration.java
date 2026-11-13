package com.aspavi.auth.config;

import com.aspavi.auth.security.KeycloakRealmRoleConverter;
import com.aspavi.auth.security.TenantFilter;
import com.aspavi.auth.tenant.TenantIssuers;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

/**
 * Auto-configuration for Aspavi multi-tenant JWT authentication.
 *
 * <p>The tenant-aware transaction manager behind PostgreSQL Row-Level Security lives in
 * {@link TenantTransactionManagerAutoConfiguration}, which must run before Spring Boot's JPA
 * auto-configuration.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
public class AspavIAuthAutoConfiguration {

    // -------------------------------------------------------------------------
    // JWT decoding — multi-tenant, per-issuer caching
    // -------------------------------------------------------------------------

    /** Issuer → tenant, from {@code aspavi.auth.tenants} and {@code aspavi.auth.issuer-pattern}. */
    @Bean
    @ConditionalOnMissingBean
    public TenantIssuers tenantIssuers(AuthProperties properties) {
        return TenantIssuers.of(properties.getTenants(), properties.getIssuerPattern());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(TenantIssuers tenantIssuers, AuthProperties properties) {
        return new MultiTenantJwtDecoder(
                tenantIssuers,
                properties.getIssuerCache().getMaxSize(),
                properties.getIssuerCache().getUnknownIssuerTtl());
    }

    // -------------------------------------------------------------------------
    // Keycloak role mapping
    //
    // JwtGrantedAuthoritiesConverter does NOT support dot-notation paths like
    // "realm_access.roles". KeycloakRealmRoleConverter extracts the nested claim.
    //
    // Spring Security's JwtConfigurer picks this bean up from the context even when
    // a SecurityConfig does not pass it to .jwt(...) explicitly.
    // -------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return jwtConverter;
    }

    // -------------------------------------------------------------------------
    // Tenant filter — tenant of the issuing realm, checked against the tenant_id
    // claim, stored in TenantContext
    // -------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public TenantFilter tenantFilter(TenantIssuers tenantIssuers) {
        return new TenantFilter(tenantIssuers);
    }
}
