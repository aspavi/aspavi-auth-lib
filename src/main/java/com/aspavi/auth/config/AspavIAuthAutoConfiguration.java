package com.aspavi.auth.config;

import com.aspavi.auth.security.TenantFilter;
import com.aspavi.auth.tenant.TenantAwareJpaTransactionManager;
import jakarta.persistence.EntityManagerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import javax.sql.DataSource;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

/**
 * Auto-configuration for Aspavi multi-tenant JWT authentication and
 * PostgreSQL Row-Level Security support.
 *
 * <p>{@code @AutoConfiguration(after = HibernateJpaAutoConfiguration.class)} ensures
 * this runs after Spring Boot's JPA auto-config has registered the
 * {@code EntityManagerFactory}. We then replace the default
 * {@code JpaTransactionManager} with our tenant-aware subclass.
 */
@AutoConfiguration(afterName = "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration")
@EnableConfigurationProperties(AuthProperties.class)
public class AspavIAuthAutoConfiguration {

    // -------------------------------------------------------------------------
    // JWT decoding — multi-tenant, per-issuer caching
    // -------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(AuthProperties properties) {
        return new MultiTenantJwtDecoder(properties.getTenants());
    }

    // -------------------------------------------------------------------------
    // Keycloak role mapping
    //
    // JwtGrantedAuthoritiesConverter does NOT support dot-notation paths like
    // "realm_access.roles". We must extract the nested claim manually.
    // -------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess == null || !realmAccess.containsKey("roles")) {
                return Collections.emptyList();
            }
            @SuppressWarnings("unchecked")
            Collection<String> roles = (Collection<String>) realmAccess.get("roles");
            return roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        });
        return jwtConverter;
    }

    // -------------------------------------------------------------------------
    // Tenant filter — extracts tenant_id claim and stores in TenantContext
    // -------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public TenantFilter tenantFilter() {
        return new TenantFilter();
    }

    // -------------------------------------------------------------------------
    // Tenant-aware transaction manager
    //
    // Replaces the default JpaTransactionManager with our subclass that calls
    // SET LOCAL app.current_tenant inside doBegin(), guaranteeing the variable
    // is set on the transaction connection before any Hibernate SQL executes.
    //
    // @Primary ensures this bean wins over the default one registered by
    // HibernateJpaAutoConfiguration. No @ConditionalOnMissingBean here —
    // we always want our implementation to be active.
    // -------------------------------------------------------------------------

    @Bean
    @Primary
    @ConditionalOnBean({DataSource.class, EntityManagerFactory.class})
    public TenantAwareJpaTransactionManager transactionManager(
            EntityManagerFactory entityManagerFactory,
            DataSource dataSource) {
        TenantAwareJpaTransactionManager tm = new TenantAwareJpaTransactionManager();
        tm.setEntityManagerFactory(entityManagerFactory);
        tm.setDataSource(dataSource);
        return tm;
    }
}
