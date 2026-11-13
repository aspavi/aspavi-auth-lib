package com.aspavi.auth.config;

import com.aspavi.auth.security.TenantFilter;
import com.aspavi.auth.tenant.TenantAwareJpaTransactionManager;
import com.aspavi.auth.tenant.TenantIssuers;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AspavIAuthAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AspavIAuthAutoConfiguration.class))
            .withPropertyValues("aspavi.auth.tenants.acme=https://kc.example.com/realms/rrhh-tenant-acme");

    @Test
    void registersSecurityBeans() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(JwtDecoder.class);
            assertThat(context.getBean(JwtDecoder.class)).isInstanceOf(MultiTenantJwtDecoder.class);
            assertThat(context).hasSingleBean(JwtAuthenticationConverter.class);
            assertThat(context).hasSingleBean(TenantFilter.class);
            assertThat(context).hasSingleBean(TenantIssuers.class);
        });
    }

    @Test
    void jwtAuthenticationConverterMapsRealmRolesWithoutPrefix() {
        runner.run(context -> {
            JwtAuthenticationConverter converter = context.getBean(JwtAuthenticationConverter.class);
            Jwt jwt = Jwt.withTokenValue("token")
                    .header("alg", "none")
                    .subject("user-1")
                    .issuedAt(Instant.now())
                    .claim("realm_access", Map.of("roles", List.of("employee:read", "ADMIN_RRHH")))
                    .build();

            List<String> authorities = converter.convert(jwt).getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            assertThat(authorities).contains("employee:read", "ADMIN_RRHH");
            assertThat(authorities).noneMatch(a -> a.startsWith("ROLE_") || a.startsWith("SCOPE_"));
        });
    }

    @Test
    void backsOffWhenServiceDeclaresItsOwnConverter() {
        runner.withUserConfiguration(CustomConverterConfig.class).run(context -> {
            assertThat(context).hasSingleBean(JwtAuthenticationConverter.class);
            assertThat(context.getBean(JwtAuthenticationConverter.class))
                    .isSameAs(CustomConverterConfig.CUSTOM);
        });
    }

    @Test
    void tenantIssuersComeFromTheMapAndThePattern() {
        runner.withPropertyValues("aspavi.auth.issuer-pattern=https://kc.example.com/realms/rrhh-tenant-{tenant}")
                .run(context -> {
                    TenantIssuers issuers = context.getBean(TenantIssuers.class);
                    assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-acme")).contains("acme");
                    assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-brand-new")).contains("brand-new");
                    assertThat(issuers.tenantFor("https://kc.example.com/realms/master")).isEmpty();
                });
    }

    @Test
    void worksWithOnlyTheMap() {
        runner.run(context -> {
            TenantIssuers issuers = context.getBean(TenantIssuers.class);
            assertThat(issuers.issuerPattern()).isNull();
            assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-acme")).contains("acme");
            assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-other")).isEmpty();
        });
    }

    @Test
    void failsToStartWithAPatternWithoutPlaceholder() {
        runner.withPropertyValues("aspavi.auth.issuer-pattern=https://kc.example.com/realms/rrhh-tenant-acme")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure().rootCause().hasMessageContaining("{tenant}"));
    }

    @Test
    void bindsTheCacheSettings() {
        runner.withPropertyValues(
                        "aspavi.auth.issuer-cache.max-size=7",
                        "aspavi.auth.issuer-cache.unknown-issuer-ttl=30s")
                .run(context -> {
                    AuthProperties properties = context.getBean(AuthProperties.class);
                    assertThat(properties.getIssuerCache().getMaxSize()).isEqualTo(7);
                    assertThat(properties.getIssuerCache().getUnknownIssuerTtl()).isEqualTo(Duration.ofSeconds(30));
                });
    }

    @Test
    void failsToStartWithAnEmptyDecoderCache() {
        runner.withPropertyValues("aspavi.auth.issuer-cache.max-size=0")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure().rootCause().hasMessageContaining("max-size"));
    }

    @Test
    void theTenantAwareTransactionManagerIsTheOnlyOneAndIsNamedTransactionManager() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        AspavIAuthAutoConfiguration.class,
                        TenantTransactionManagerAutoConfiguration.class,
                        DataSourceAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class))
                .withPropertyValues(
                        "spring.datasource.url=jdbc:h2:mem:autoconfig;DB_CLOSE_DELAY=-1",
                        "spring.datasource.username=sa")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(TenantAwareJpaTransactionManager.class);
                    assertThat(context.getBean(PlatformTransactionManager.class))
                            .isInstanceOf(TenantAwareJpaTransactionManager.class);
                    assertThat(context.getBean(TenantAwareJpaTransactionManager.class).isStrict()).isFalse();
                    assertThat(context.getBeansOfType(PlatformTransactionManager.class)).hasSize(1);
                    assertThat(context.getBean("transactionManager"))
                            .isSameAs(context.getBean(TenantAwareJpaTransactionManager.class));
                    assertThat(context.getBean("tenantAwareTransactionManager"))
                            .isSameAs(context.getBean(TenantAwareJpaTransactionManager.class));
                });
    }

    @Test
    void strictTenantModeIsBoundToTheTransactionManager() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        AspavIAuthAutoConfiguration.class,
                        TenantTransactionManagerAutoConfiguration.class,
                        DataSourceAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class))
                .withPropertyValues(
                        "spring.datasource.url=jdbc:h2:mem:strict;DB_CLOSE_DELAY=-1",
                        "spring.datasource.username=sa",
                        "aspavi.auth.tenant.strict=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(TenantAwareJpaTransactionManager.class).isStrict()).isTrue();
                });
    }

    @Test
    void startsWithoutJpaOnTheClasspath() {
        runner.withConfiguration(AutoConfigurations.of(TenantTransactionManagerAutoConfiguration.class))
                .withClassLoader(new FilteredClassLoader("jakarta.persistence.", "org.springframework.orm."))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                    assertThat(context).hasSingleBean(JwtAuthenticationConverter.class);
                    assertThat(context).hasSingleBean(TenantFilter.class);
                    assertThat(context).doesNotHaveBean("tenantAwareTransactionManager");
                    assertThat(context).doesNotHaveBean("transactionManager");
                });
    }

    @Test
    void aServiceThatDeclaresItsOwnTransactionManagerFailsToStart() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        AspavIAuthAutoConfiguration.class,
                        TenantTransactionManagerAutoConfiguration.class,
                        DataSourceAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class))
                .withUserConfiguration(OwnTransactionManagerConfig.class)
                .withPropertyValues(
                        "spring.datasource.url=jdbc:h2:mem:own-tm;DB_CLOSE_DELAY=-1",
                        "spring.datasource.username=sa")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure().hasMessageContaining("transactionManager"));
    }

    @Configuration(proxyBeanMethods = false)
    static class OwnTransactionManagerConfig {
        @Bean
        PlatformTransactionManager transactionManager(jakarta.persistence.EntityManagerFactory emf) {
            return new org.springframework.orm.jpa.JpaTransactionManager(emf);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomConverterConfig {
        static final JwtAuthenticationConverter CUSTOM = new JwtAuthenticationConverter();

        @Bean
        JwtAuthenticationConverter customJwtAuthenticationConverter() {
            return CUSTOM;
        }
    }
}
