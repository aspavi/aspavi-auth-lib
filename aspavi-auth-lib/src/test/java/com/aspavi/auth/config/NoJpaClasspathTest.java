package com.aspavi.auth.config;

import com.aspavi.auth.security.TenantFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs in the {@code no-jpa-classpath} surefire execution, whose classpath excludes JPA,
 * Hibernate and spring-orm (see the module pom), like a service without a database.
 * The default execution skips it.
 */
class NoJpaClasspathTest {

    @Test
    void classpathReallyHasNoJpa() {
        ClassLoader classLoader = getClass().getClassLoader();
        assertThat(ClassUtils.isPresent("jakarta.persistence.EntityManagerFactory", classLoader)).isFalse();
        assertThat(ClassUtils.isPresent("org.springframework.orm.jpa.JpaTransactionManager", classLoader)).isFalse();
    }

    @Test
    void startsWithSecurityBeansAndWithoutTenantAwareTransactionManager() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        AspavIAuthAutoConfiguration.class, TenantTransactionManagerAutoConfiguration.class))
                .withPropertyValues("aspavi.auth.tenants.acme=https://kc.example.com/realms/rrhh-tenant-acme")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                    assertThat(context).hasSingleBean(JwtAuthenticationConverter.class);
                    assertThat(context).hasSingleBean(TenantFilter.class);
                    assertThat(context).doesNotHaveBean("tenantAwareTransactionManager");
                    assertThat(context).doesNotHaveBean("transactionManager");
                });
    }
}
