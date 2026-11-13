package com.aspavi.auth.tenant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.TransactionDefinition;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * A {@link JpaTransactionManager} that sets the PostgreSQL variable {@code app.current_tenant} to the
 * tenant of {@link TenantContext} at the start of each transaction, so that row-level security (RLS)
 * policies filter by it.
 *
 * <p>Right after Spring opens the transaction it runs
 * {@code SELECT set_config('app.current_tenant', ?, true)} on the transaction's JDBC connection, with
 * the tenant id as a bound parameter. {@code true} makes the value local to the transaction, like
 * {@code SET LOCAL}: it is gone after commit or rollback, so a pooled connection never carries the
 * tenant of a previous transaction. This runs before Hibernate issues any SQL.
 *
 * <h3>Without tenant</h3>
 * <ul>
 *   <li>Default ({@link #setStrict(boolean) strict} = false): the variable is not set and the
 *       transaction runs; what it sees depends on the policies.</li>
 *   <li>Strict ({@code aspavi.auth.tenant.strict=true}): the transaction does not start and
 *       {@link MissingTenantException} names it.</li>
 *   <li>Inside {@link TenantContext#runWithoutTenant(java.util.function.Supplier)}: allowed in both
 *       modes, logged at DEBUG, and the variable is not set.</li>
 * </ul>
 *
 * <h3>Why this approach</h3>
 * <p>Alternative approaches (AOP, {@code StatementInspector}, {@code ConnectionProvider})
 * all suffer from ordering or connection-identity issues: they either run before the
 * transaction connection is bound, or operate on a different connection than Hibernate.
 * Subclassing {@code JpaTransactionManager} and overriding {@code doBegin} is the
 * only approach that is guaranteed to run on the correct connection at exactly
 * the right moment.
 *
 * <p>Registered automatically via
 * {@link com.aspavi.auth.config.AspavIAuthAutoConfiguration} as the primary
 * {@code PlatformTransactionManager} bean (replaces the default Spring Boot one).
 */
public class TenantAwareJpaTransactionManager extends JpaTransactionManager {

    static final String SET_TENANT_SQL = "SELECT set_config('app.current_tenant', ?, true)";

    private static final Logger log = LoggerFactory.getLogger(TenantAwareJpaTransactionManager.class);

    private boolean strict;

    /** With {@code true}, a transaction without tenant outside {@code runWithoutTenant} fails. */
    public void setStrict(boolean strict) {
        this.strict = strict;
    }

    public boolean isStrict() {
        return strict;
    }

    @Override
    protected void doBegin(Object transaction, TransactionDefinition definition) {
        String tenantId = TenantContext.getTenantId();
        boolean hasTenant = tenantId != null && !tenantId.isBlank();

        // Checked before the transaction opens, so a refusal leaves nothing bound to the thread.
        if (!hasTenant) {
            if (TenantContext.isRunningWithoutTenant()) {
                log.debug("Transaction '{}' runs without tenant (TenantContext.runWithoutTenant):"
                        + " app.current_tenant not set", nameOf(definition));
            } else if (strict) {
                throw new MissingTenantException(nameOf(definition));
            }
        }

        // Let Spring open the transaction and bind the JDBC connection first
        super.doBegin(transaction, definition);

        if (!hasTenant) {
            return;
        }

        DataSource dataSource = getDataSource();
        if (dataSource == null) {
            log.warn("TenantAwareJpaTransactionManager: no DataSource configured, app.current_tenant not set");
            return;
        }

        // DataSourceUtils.getConnection() returns the transaction-bound connection
        Connection connection = DataSourceUtils.getConnection(dataSource);
        try (PreparedStatement statement = connection.prepareStatement(SET_TENANT_SQL)) {
            statement.setString(1, tenantId);
            statement.execute();
            log.debug("Transaction '{}': app.current_tenant = '{}'", nameOf(definition), tenantId);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to set app.current_tenant for tenant '" + tenantId + "'", e);
        } finally {
            DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }

    private static String nameOf(TransactionDefinition definition) {
        String name = definition.getName();
        return name == null || name.isBlank() ? "(unnamed transaction)" : name;
    }
}
