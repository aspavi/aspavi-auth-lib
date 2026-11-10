package com.aspavi.auth.config;

import com.aspavi.auth.security.KeycloakRealmRoleConverter;
import com.aspavi.auth.security.TenantFilter;
import com.aspavi.auth.tenant.TenantAwareJpaTransactionManager;
import jakarta.persistence.EntityManagerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import javax.sql.DataSource;

/**
 * Auto-configuration for Aspavi multi-tenant JWT authentication and
 * PostgreSQL Row-Level Security support.
 *
 * <p>Runs after Spring Boot's Hibernate JPA auto-configuration so that the
 * {@code EntityManagerFactory} is already registered when the
 * {@code @ConditionalOnBean} of the tenant-aware transaction manager is evaluated.
 * Spring Boot 4 moved that class to {@code org.springframework.boot.hibernate.autoconfigure};
 * the Boot 3 name is kept so the ordering also holds there. An unknown name is ignored.
 */
@AutoConfiguration(afterName = {
        "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration",
        "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration"
})
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
    //
    // It lives in a nested configuration guarded by @ConditionalOnClass so that a
    // service without JPA on the classpath (no database) still starts: Spring
    // introspects the @Bean method signatures of a configuration class, and
    // EntityManagerFactory / JpaTransactionManager must not appear in the outer one.
    // -------------------------------------------------------------------------

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {
            "jakarta.persistence.EntityManagerFactory",
            "org.springframework.orm.jpa.JpaTransactionManager"
    })
    static class TenantAwareTransactionManagerConfiguration {

        @Bean
        @Primary
        @ConditionalOnBean({DataSource.class, EntityManagerFactory.class})
        public TenantAwareJpaTransactionManager tenantAwareTransactionManager(
                EntityManagerFactory entityManagerFactory,
                DataSource dataSource) {
            TenantAwareJpaTransactionManager tm = new TenantAwareJpaTransactionManager();
            tm.setEntityManagerFactory(entityManagerFactory);
            tm.setDataSource(dataSource);
            return tm;
        }
    }
}
