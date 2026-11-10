package com.aspavi.auth.tenant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.TransactionDefinition;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * A {@link JpaTransactionManager} that automatically sets the PostgreSQL session
 * variable {@code app.current_tenant} after each transaction begins.
 *
 * <p>This subclass overrides {@link #doBegin(Object, TransactionDefinition)} to
 * execute {@code SET LOCAL app.current_tenant = '<tenantId>'} on the transaction's
 * JDBC connection immediately after Spring opens the transaction. This guarantees
 * that the variable is set before Hibernate issues any SQL statement, so the
 * PostgreSQL Row-Level Security (RLS) policy can enforce tenant isolation.
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

    private static final Logger log = LoggerFactory.getLogger(TenantAwareJpaTransactionManager.class);

    @Override
    protected void doBegin(Object transaction, TransactionDefinition definition) {
        // Let Spring open the transaction and bind the JDBC connection first
        super.doBegin(transaction, definition);

        // Now the connection is bound to the current thread — set the tenant variable
        String tenantId = TenantContext.getTenantId();
        if (tenantId == null || tenantId.isBlank()) {
            return;
        }

        javax.sql.DataSource dataSource = getDataSource();
        if (dataSource == null) {
            log.warn("TenantAwareJpaTransactionManager: no DataSource configured, " +
                     "SET LOCAL app.current_tenant skipped");
            return;
        }

        // DataSourceUtils.getConnection() returns the transaction-bound connection
        Connection connection = DataSourceUtils.getConnection(dataSource);
        String safeTenantId = tenantId.replace("'", "''");

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("SET LOCAL app.current_tenant = '" + safeTenantId + "'");
            log.debug("TenantAwareJpaTransactionManager.doBegin: " +
                      "SET LOCAL app.current_tenant = '{}'", tenantId);
        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to SET LOCAL app.current_tenant for tenant '" + tenantId + "'", e);
        } finally {
            DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }
}
