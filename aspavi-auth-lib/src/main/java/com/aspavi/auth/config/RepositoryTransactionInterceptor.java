package com.aspavi.auth.config;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Runs a repository method that is called with no transaction active in a transaction of the lib's
 * transaction manager, so that it sets {@code app.current_tenant} and strict mode applies to it.
 *
 * <p>Spring Data gives a transaction only to the methods it implements ({@code SimpleJpaRepository},
 * read-only by default). Query methods declared on the repository interface (derived
 * {@code findBy…}/{@code countBy…}/{@code deleteBy…}, {@code @Query}, default methods, custom
 * fragments) get none: outside a transaction they would run in auto-commit, without tenant, and
 * strict mode would not see them.
 *
 * <ul>
 *   <li>A transaction already active (of the caller, or the one Spring Data opened for its own
 *       {@code @Transactional} methods) is used as it is: no new one, no rollback-only mark when
 *       the method throws.</li>
 *   <li>Otherwise the method runs in a new transaction named {@code <repository>.<method>}. It is
 *       not read-only: a derived {@code deleteBy…} or a default method that saves must flush.</li>
 * </ul>
 *
 * <p>It sits inside Spring Data's transaction and exception translation interceptors, so a
 * {@code MissingTenantException} reaches the caller like from any other repository method.
 */
final class RepositoryTransactionInterceptor implements MethodInterceptor {

    private final ObjectProvider<PlatformTransactionManager> transactionManager;
    private final String repositoryName;

    RepositoryTransactionInterceptor(ObjectProvider<PlatformTransactionManager> transactionManager,
                                     Class<?> repositoryInterface) {
        this.transactionManager = transactionManager;
        this.repositoryName = repositoryInterface.getName();
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        if (invocation.getMethod().getDeclaringClass() == Object.class
                || TransactionSynchronizationManager.isActualTransactionActive()) {
            return invocation.proceed();
        }

        TransactionTemplate transaction = new TransactionTemplate(transactionManager.getObject());
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRED);
        transaction.setName(repositoryName + "." + invocation.getMethod().getName());

        Outcome outcome = transaction.execute(status -> {
            try {
                return new Outcome(invocation.proceed(), null);
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Throwable checked) {
                // Like @Transactional: a checked exception commits; it is rethrown afterwards.
                return new Outcome(null, checked);
            }
        });
        if (outcome.checked() != null) {
            throw outcome.checked();
        }
        return outcome.value();
    }

    private record Outcome(Object value, Throwable checked) {}
}
