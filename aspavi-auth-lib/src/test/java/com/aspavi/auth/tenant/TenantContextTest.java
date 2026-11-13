package com.aspavi.auth.tenant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantContextTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void runAsSetsTheTenantAndReturnsTheResult() {
        String seen = TenantContext.runAs("acme", TenantContext::getTenantId);

        assertThat(seen).isEqualTo("acme");
        assertThat(TenantContext.getTenantId()).isNull();
    }

    @Test
    void runAsNestsAndRestoresEachLevel() {
        TenantContext.setTenantId("outer");
        List<String> seen = new ArrayList<>();

        TenantContext.runAs("a", () -> {
            seen.add(TenantContext.getTenantId());
            TenantContext.runAs("b", () -> seen.add(TenantContext.getTenantId()));
            seen.add(TenantContext.getTenantId());
        });

        assertThat(seen).containsExactly("a", "b", "a");
        assertThat(TenantContext.getTenantId()).isEqualTo("outer");
    }

    @Test
    void runAsRestoresThePreviousTenantWhenTheActionThrows() {
        TenantContext.setTenantId("outer");
        IllegalStateException failure = new IllegalStateException("boom");

        assertThatThrownBy(() -> TenantContext.runAs("a", () -> {
            throw failure;
        })).isSameAs(failure);

        assertThat(TenantContext.getTenantId()).isEqualTo("outer");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "  "})
    void runAsNeedsATenant(String tenantId) {
        TenantContext.setTenantId("outer");

        assertThatThrownBy(() -> TenantContext.runAs(tenantId, () -> "never"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(TenantContext.getTenantId()).isEqualTo("outer");
    }

    @Test
    void runWithoutTenantHidesTheTenantAndRestoresIt() {
        TenantContext.setTenantId("outer");

        String seen = TenantContext.runWithoutTenant(() -> {
            assertThat(TenantContext.isRunningWithoutTenant()).isTrue();
            return TenantContext.getTenantId();
        });

        assertThat(seen).isNull();
        assertThat(TenantContext.getTenantId()).isEqualTo("outer");
        assertThat(TenantContext.isRunningWithoutTenant()).isFalse();
    }

    @Test
    void runWithoutTenantRestoresWhenTheActionThrows() {
        TenantContext.setTenantId("outer");

        assertThatThrownBy(() -> TenantContext.runWithoutTenant(() -> {
            throw new IllegalStateException("boom");
        })).hasMessage("boom");

        assertThat(TenantContext.getTenantId()).isEqualTo("outer");
        assertThat(TenantContext.isRunningWithoutTenant()).isFalse();
    }

    @Test
    void runAsInsideRunWithoutTenantWorksAsTheTenantAndGoesBack() {
        List<String> seen = new ArrayList<>();

        TenantContext.runWithoutTenant(() -> {
            TenantContext.runAs("a", () -> {
                seen.add(TenantContext.getTenantId());
                seen.add("without=" + TenantContext.isRunningWithoutTenant());
            });
            seen.add(TenantContext.getTenantId());
            seen.add("without=" + TenantContext.isRunningWithoutTenant());
        });

        assertThat(seen).containsExactly("a", "without=false", null, "without=true");
        assertThat(TenantContext.isRunningWithoutTenant()).isFalse();
    }

    @Test
    void clearAlsoLeavesRunWithoutTenantMode() {
        TenantContext.runWithoutTenant(() -> {
            TenantContext.clear();
            assertThat(TenantContext.isRunningWithoutTenant()).isFalse();
        });
    }

    @Test
    void requiredTenantIdFailsWithoutTenant() {
        assertThatThrownBy(TenantContext::getRequiredTenantId).isInstanceOf(IllegalStateException.class);
        assertThat(TenantContext.runAs("acme", TenantContext::getRequiredTenantId)).isEqualTo("acme");
    }
}
