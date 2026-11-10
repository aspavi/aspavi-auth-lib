package com.aspavi.auth.security;

/**
 * Names of the JWT claims issued by the Aspavi Keycloak realms.
 */
public final class AspaviClaims {

    /** Tenant identifier, added by a hardcoded-claim mapper on every client. */
    public static final String TENANT_ID = "tenant_id";

    /** Employee identifier (UUID) of the user, added by a user-attribute mapper. */
    public static final String EMPLOYEE_ID = "employee_id";

    /** Keycloak's realm access claim; holds the effective realm roles under {@link #ROLES}. */
    public static final String REALM_ACCESS = "realm_access";

    /** Key of the role list inside {@link #REALM_ACCESS}. */
    public static final String ROLES = "roles";

    private AspaviClaims() {}
}
