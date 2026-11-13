package com.aspavi.auth.tenant;

import java.util.Objects;
import java.util.function.Supplier;

/**
 * Thread-local holder for the current tenant identifier.
 *
 * <p>{@code TenantFilter} sets it for each authenticated request and clears it afterwards. Work that
 * does not come from a request (scheduled jobs, message consumers, start-up tasks) sets it with
 * {@link #runAs(String, Supplier)}, or, when it belongs to no tenant at all, declares so with
 * {@link #runWithoutTenant(Supplier)}.
 */
public final class TenantContext {

    private static final ThreadLocal<String> CURRENT_TENANT = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> WITHOUT_TENANT = new ThreadLocal<>();

    private TenantContext() {}

    public static void setTenantId(String tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    public static String getTenantId() {
        return CURRENT_TENANT.get();
    }

    /**
     * Returns the tenant ID or throws if not set.
     * Use in service layer code that requires a tenant to be present.
     */
    public static String getRequiredTenantId() {
        String tenantId = CURRENT_TENANT.get();
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalStateException("Tenant ID not set in current context");
        }
        return tenantId;
    }

    /** Removes the tenant and leaves {@link #runWithoutTenant(Supplier)} mode. */
    public static void clear() {
        CURRENT_TENANT.remove();
        WITHOUT_TENANT.remove();
    }

    /**
     * Runs {@code action} as {@code tenantId}: transactions started inside it set
     * {@code app.current_tenant} to that tenant. The previous context is restored afterwards, also
     * when {@code action} throws, so calls can be nested.
     *
     * @throws IllegalArgumentException if {@code tenantId} is null or blank
     */
    public static <T> T runAs(String tenantId, Supplier<T> action) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("runAs needs a tenant id, got '" + tenantId + "'");
        }
        Objects.requireNonNull(action, "action");
        return runWith(tenantId, false, action);
    }

    /** {@link #runAs(String, Supplier)} for an action without result. */
    public static void runAs(String tenantId, Runnable action) {
        Objects.requireNonNull(action, "action");
        runAs(tenantId, () -> {
            action.run();
            return null;
        });
    }

    /**
     * Runs {@code action} explicitly without tenant, for system work that belongs to no tenant, such
     * as calling the {@code SECURITY DEFINER} functions that list the tenants with pending work.
     *
     * <p>Inside it, a transaction may start without tenant even in strict mode
     * ({@code aspavi.auth.tenant.strict=true}); {@code app.current_tenant} is not set, so row-level
     * security shows no tenant's rows. A tenant set before is hidden and restored afterwards, also
     * when {@code action} throws.
     */
    public static <T> T runWithoutTenant(Supplier<T> action) {
        Objects.requireNonNull(action, "action");
        return runWith(null, true, action);
    }

    /** {@link #runWithoutTenant(Supplier)} for an action without result. */
    public static void runWithoutTenant(Runnable action) {
        Objects.requireNonNull(action, "action");
        runWithoutTenant(() -> {
            action.run();
            return null;
        });
    }

    /** Whether the current thread is inside {@link #runWithoutTenant(Supplier)} and no tenant is set. */
    public static boolean isRunningWithoutTenant() {
        return Boolean.TRUE.equals(WITHOUT_TENANT.get());
    }

    private static <T> T runWith(String tenantId, boolean withoutTenant, Supplier<T> action) {
        String previousTenant = CURRENT_TENANT.get();
        Boolean previousWithoutTenant = WITHOUT_TENANT.get();
        set(tenantId, withoutTenant ? Boolean.TRUE : null);
        try {
            return action.get();
        } finally {
            set(previousTenant, previousWithoutTenant);
        }
    }

    private static void set(String tenantId, Boolean withoutTenant) {
        if (tenantId == null) {
            CURRENT_TENANT.remove();
        } else {
            CURRENT_TENANT.set(tenantId);
        }
        if (withoutTenant == null) {
            WITHOUT_TENANT.remove();
        } else {
            WITHOUT_TENANT.set(withoutTenant);
        }
    }
}
