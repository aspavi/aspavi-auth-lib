package com.aspavi.auth.tenant;

/**
 * A transaction started without tenant in strict mode ({@code aspavi.auth.tenant.strict=true}),
 * outside {@link TenantContext#runWithoutTenant(java.util.function.Supplier)}. Without tenant,
 * row-level security would show and accept no row, so the access fails here, visibly, instead.
 */
public class MissingTenantException extends IllegalStateException {

    private final String transactionName;

    public MissingTenantException(String transactionName) {
        super("Transaction '" + transactionName + "' started without tenant: set one with TenantFilter or"
                + " TenantContext.runAs(tenantId, ...), or wrap system work that belongs to no tenant in"
                + " TenantContext.runWithoutTenant(...)");
        this.transactionName = transactionName;
    }

    /** The name of the transaction, usually {@code <class>.<method>} of the {@code @Transactional} method. */
    public String getTransactionName() {
        return transactionName;
    }
}
