package com.aspavi.auth.config;

import com.aspavi.auth.tenant.TenantAwareJpaTransactionManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnSingleCandidate;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.transaction.autoconfigure.TransactionManagerCustomizers;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;

/**
 * Makes {@link TenantAwareJpaTransactionManager} the only JPA transaction manager of the context,
 * under the bean name {@code transactionManager}.
 *
 * <p>The name matters: Spring Data repositories do not take the {@code @Primary} transaction
 * manager, they look it up by name ({@code transactionManagerRef}, {@code "transactionManager"} by
 * default). Before 1.3.1 the lib's manager was an extra bean and Spring Boot kept its own
 * {@code JpaTransactionManager} as {@code transactionManager}, so a repository called without an
 * outer transaction set no tenant and strict mode did not apply to it.
 *
 * <p>This auto-configuration runs before Spring Boot's Hibernate JPA auto-configuration, whose
 * {@code transactionManager} is {@code @ConditionalOnMissingBean(TransactionManager.class)} and so
 * backs off. The manager finds the {@code EntityManagerFactory} in the bean factory when it starts,
 * as Spring Boot's own does, and {@code spring.transaction.*} customizations apply to it.
 *
 * <p>It is always registered when JPA is on the classpath and there is a single {@code DataSource}:
 * a service that declares its own {@code transactionManager} bean fails to start instead of losing
 * tenant isolation without notice.
 */
@AutoConfiguration(
        afterName = {
                "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
                "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration"
        },
        beforeName = {
                "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration",
                "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration"
        })
@ConditionalOnClass(name = {
        "jakarta.persistence.EntityManagerFactory",
        "org.springframework.orm.jpa.JpaTransactionManager",
        "org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean",
        "org.springframework.boot.transaction.autoconfigure.TransactionManagerCustomizers"
})
@ConditionalOnSingleCandidate(DataSource.class)
@EnableConfigurationProperties(AuthProperties.class)
public class TenantTransactionManagerAutoConfiguration {

    /** Bean name that Spring Data repositories and Spring Boot use for the transaction manager. */
    public static final String TRANSACTION_MANAGER = "transactionManager";

    /** Name of the bean before 1.3.1, kept as an alias. */
    public static final String LEGACY_NAME = "tenantAwareTransactionManager";

    @Bean(name = {TRANSACTION_MANAGER, LEGACY_NAME})
    @Primary
    public TenantAwareJpaTransactionManager transactionManager(
            AuthProperties properties,
            ObjectProvider<TransactionManagerCustomizers> transactionManagerCustomizers) {
        TenantAwareJpaTransactionManager transactionManager = new TenantAwareJpaTransactionManager();
        transactionManager.setStrict(properties.getTenant().isStrict());
        transactionManagerCustomizers.ifAvailable(customizers -> customizers.customize(transactionManager));
        return transactionManager;
    }
}
