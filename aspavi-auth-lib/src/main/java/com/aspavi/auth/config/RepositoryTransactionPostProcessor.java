package com.aspavi.auth.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Adds {@link RepositoryTransactionInterceptor} to every Spring Data JPA repository.
 *
 * <p>It customizes each {@link JpaRepositoryFactoryBean} before it builds its repository; the
 * interceptor is added after Spring Data's own transaction interceptor, so it runs inside it.
 */
final class RepositoryTransactionPostProcessor implements BeanPostProcessor {

    private final ObjectProvider<PlatformTransactionManager> transactionManager;

    RepositoryTransactionPostProcessor(ObjectProvider<PlatformTransactionManager> transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) {
        if (bean instanceof JpaRepositoryFactoryBean<?, ?, ?> factoryBean) {
            factoryBean.addRepositoryFactoryCustomizer(factory -> factory.addRepositoryProxyPostProcessor(
                    (proxy, repository) -> proxy.addAdvice(
                            new RepositoryTransactionInterceptor(transactionManager, repository.getRepositoryInterface()))));
        }
        return bean;
    }
}
