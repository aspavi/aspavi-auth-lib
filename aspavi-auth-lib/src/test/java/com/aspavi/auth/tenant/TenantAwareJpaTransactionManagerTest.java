package com.aspavi.auth.tenant;

import com.aspavi.auth.config.AspavIAuthAutoConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The transaction manager against a real PostgreSQL with a strict row-level security policy, used
 * through a role that is neither the owner nor BYPASSRLS, as the services run.
 */
class TenantAwareJpaTransactionManagerTest {

    private static final String APP = "item_app";
    private static final String APP_PASSWORD = "app-pw";
    private static final String QUOTED = "o'brien'); DROP TABLE item; --";

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine");

    @BeforeAll
    static void startDatabase() throws SQLException {
        POSTGRES.start();
        try (Connection owner = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement sql = owner.createStatement()) {
            sql.execute("CREATE TABLE item (id serial PRIMARY KEY, tenant_id text NOT NULL, name text NOT NULL)");
            sql.execute("ALTER TABLE item ENABLE ROW LEVEL SECURITY");
            sql.execute("ALTER TABLE item FORCE ROW LEVEL SECURITY");
            sql.execute("CREATE POLICY item_tenant ON item"
                    + " USING (tenant_id = current_setting('app.current_tenant', true))"
                    + " WITH CHECK (tenant_id = current_setting('app.current_tenant', true))");
            sql.execute("CREATE ROLE " + APP + " LOGIN PASSWORD '" + APP_PASSWORD + "'");
            sql.execute("GRANT SELECT, INSERT ON item TO " + APP);
            sql.execute("GRANT USAGE ON SEQUENCE item_id_seq TO " + APP);
            sql.execute("ALTER TABLE item DISABLE ROW LEVEL SECURITY");
            sql.execute("INSERT INTO item (tenant_id, name) VALUES ('acme', 'acme-1'), ('acme', 'acme-2'),"
                    + " ('beta', 'beta-1'), ('" + QUOTED.replace("'", "''") + "', 'quoted-1')");
            sql.execute("ALTER TABLE item ENABLE ROW LEVEL SECURITY");
        }
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    AspavIAuthAutoConfiguration.class,
                    DataSourceAutoConfiguration.class,
                    HibernateJpaAutoConfiguration.class))
            .withPropertyValues(
                    "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                    "spring.datasource.username=" + APP,
                    "spring.datasource.password=" + APP_PASSWORD,
                    // One connection: every transaction reuses it, so a tenant left behind would show.
                    "spring.datasource.hikari.maximum-pool-size=1");

    @Test
    void aTransactionSeesOnlyTheRowsOfItsTenant() {
        withDatabase(false, db -> {
            assertThat(TenantContext.runAs("acme", () -> db.names())).containsExactly("acme-1", "acme-2");
            assertThat(TenantContext.runAs("beta", () -> db.names())).containsExactly("beta-1");
        });
    }

    @Test
    void theTenantIsABoundValueSoAQuoteBreaksNothing() {
        withDatabase(false, db -> {
            assertThat(TenantContext.runAs(QUOTED, () -> db.currentTenant())).isEqualTo(QUOTED);
            assertThat(TenantContext.runAs(QUOTED, () -> db.names())).containsExactly("quoted-1");
            assertThat(TenantContext.runAs("acme", () -> db.names())).hasSize(2);
        });
    }

    @Test
    void theTenantDoesNotOutliveItsTransaction() {
        withDatabase(false, db -> {
            TenantContext.runAs("acme", () -> db.names());

            assertThat(db.currentTenant()).isNullOrEmpty();
            assertThat(db.names()).isEmpty();
        });
    }

    @Test
    void byDefaultATransactionWithoutTenantRunsAndSeesNothingUnderAStrictPolicy() {
        withDatabase(false, db -> {
            assertThat(db.manager().isStrict()).isFalse();
            assertThat(db.names()).isEmpty();
        });
    }

    @Test
    void inStrictModeATransactionWithoutTenantFailsAndNamesIt() {
        withDatabase(true, db -> {
            TransactionTemplate named = new TransactionTemplate(db.manager());
            named.setName("NightlyReport.run");

            assertThatThrownBy(() -> named.execute(status -> db.jdbc().queryForList("SELECT name FROM item")))
                    .isInstanceOf(MissingTenantException.class)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("NightlyReport.run")
                    .satisfies(e -> assertThat(((MissingTenantException) e).getTransactionName())
                            .isEqualTo("NightlyReport.run"));
            assertThat(TransactionSynchronizationManager.getResourceMap()).isEmpty();
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        });
    }

    @Test
    void inStrictModeTheConnectionIsStillUsableAfterARefusal() {
        withDatabase(true, db -> {
            assertThatThrownBy(db::names).isInstanceOf(MissingTenantException.class);

            assertThat(TenantContext.runAs("acme", () -> db.names())).hasSize(2);
        });
    }

    @Test
    void inStrictModeRunWithoutTenantIsAllowedAndSetsNoTenant() {
        withDatabase(true, db -> TenantContext.runWithoutTenant(() -> {
            assertThat(db.currentTenant()).isNullOrEmpty();
            assertThat(db.names()).isEmpty();
            assertThatThrownBy(() -> db.insert("beta", "sneaky"))
                    .rootCause().hasMessageContaining("new row violates row-level security policy");
        }));
    }

    @Test
    void inStrictModeRunAsInsideRunWithoutTenantWorksAsTheTenant() {
        withDatabase(true, db -> TenantContext.runWithoutTenant(() -> {
            TenantContext.runAs("gamma", () -> db.insert("gamma", "gamma-1"));
            assertThat(TenantContext.runAs("gamma", () -> db.names())).containsExactly("gamma-1");
            assertThat(db.names()).isEmpty();
        }));
    }

    @Test
    void aTenantCannotWriteRowsOfAnother() {
        withDatabase(true, db -> assertThatThrownBy(() -> TenantContext.runAs("acme", () -> db.insert("beta", "x")))
                .rootCause().hasMessageContaining("new row violates row-level security policy"));
    }

    private void withDatabase(boolean strict, Consumer<Db> test) {
        runner.withPropertyValues("aspavi.auth.tenant.strict=" + strict).run(context -> {
            assertThat(context).hasNotFailed();
            test.accept(new Db(context));
        });
    }

    private record Db(TenantAwareJpaTransactionManager manager, JdbcTemplate jdbc) {

        Db(ConfigurableApplicationContext context) {
            this((TenantAwareJpaTransactionManager) context.getBean(PlatformTransactionManager.class),
                    new JdbcTemplate(context.getBean(javax.sql.DataSource.class)));
        }

        List<String> names() {
            return new TransactionTemplate(manager).execute(
                    status -> jdbc.queryForList("SELECT name FROM item ORDER BY name", String.class));
        }

        String currentTenant() {
            return new TransactionTemplate(manager).execute(status -> jdbc.queryForObject(
                    "SELECT current_setting('app.current_tenant', true)", String.class));
        }

        int insert(String tenantId, String name) {
            return new TransactionTemplate(manager).execute(status -> jdbc.update(
                    "INSERT INTO item (tenant_id, name) VALUES (?, ?)", tenantId, name));
        }
    }
}
