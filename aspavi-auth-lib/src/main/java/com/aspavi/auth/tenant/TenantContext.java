package com.aspavi.auth.tenant;

/**
 * Thread-local holder for the current tenant identifier.
 *
 * Set by TenantFilter on every incoming request and cleared on response.
 */
public final class TenantContext {

    private static final ThreadLocal<String> CURRENT_TENANT = new ThreadLocal<>();

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

    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
