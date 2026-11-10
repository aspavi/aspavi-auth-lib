package com.aspavi.auth.config;

import com.aspavi.auth.security.TenantFilter;
import com.aspavi.auth.tenant.TenantAwareJpaTransactionManager;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.transaction.PlatformTransactionManager;

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
    void registersTenantAwareTransactionManagerAfterSpringBootJpa() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        AspavIAuthAutoConfiguration.class,
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
                });
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
