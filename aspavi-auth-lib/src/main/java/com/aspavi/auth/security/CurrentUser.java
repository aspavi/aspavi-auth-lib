package com.aspavi.auth.security;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import java.util.Optional;
import java.util.UUID;

/**
 * Static access to the identity of the user behind the current request, read from the
 * JWT in the {@link SecurityContextHolder}. Companion of
 * {@link com.aspavi.auth.tenant.TenantContext}.
 *
 * <p>Methods that need the token throw {@link AuthenticationCredentialsNotFoundException}
 * (401) when there is no JWT-authenticated user, and {@link IdentityClaimException} (403)
 * when a required claim is missing or malformed.
 *
 * <p>The identity of the current user always comes from the token: never accept
 * {@code employeeId}, {@code approverId} or {@code createdBy} for the current user from a
 * request body.
 */
public final class CurrentUser {

    private CurrentUser() {}

    /**
     * Keycloak user id ({@code sub} claim).
     *
     * @throws AuthenticationCredentialsNotFoundException if there is no JWT-authenticated user
     * @throws IdentityClaimException if the token has no {@code sub}
     */
    public static String userId() {
        return requireClaim(JwtClaimNames.SUB);
    }

    /**
     * Tenant of the user ({@code tenant_id} claim).
     *
     * @throws AuthenticationCredentialsNotFoundException if there is no JWT-authenticated user
     * @throws IdentityClaimException if the token has no {@code tenant_id}
     */
    public static String tenantId() {
        return requireClaim(AspaviClaims.TENANT_ID);
    }

    /**
     * Employee linked to the user ({@code employee_id} claim), empty when the user is not
     * an employee (e.g. a technical or external account).
     *
     * @throws AuthenticationCredentialsNotFoundException if there is no JWT-authenticated user
     * @throws IdentityClaimException if the claim is present but is not a UUID
     */
    public static Optional<UUID> employeeId() {
        String raw = jwt().getClaimAsString(AspaviClaims.EMPLOYEE_ID);
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            UUID uuid = UUID.fromString(raw);
            if (!uuid.toString().equalsIgnoreCase(raw)) {
                throw IdentityClaimException.invalid(AspaviClaims.EMPLOYEE_ID, raw);
            }
            return Optional.of(uuid);
        } catch (IllegalArgumentException e) {
            throw IdentityClaimException.invalid(AspaviClaims.EMPLOYEE_ID, raw);
        }
    }

    /**
     * Employee linked to the user; for {@code /api/v1/me/...} endpoints.
     *
     * @throws AuthenticationCredentialsNotFoundException if there is no JWT-authenticated user
     * @throws IdentityClaimException (403) if the token has no valid {@code employee_id}
     */
    public static UUID requireEmployeeId() {
        return employeeId().orElseThrow(() -> IdentityClaimException.missing(AspaviClaims.EMPLOYEE_ID));
    }

    /**
     * Whether the current user holds the given permission (e.g. {@code employee:read}),
     * using the same authorities {@code hasAuthority(...)} checks. Returns {@code false}
     * when there is no authenticated user.
     */
    public static boolean hasPermission(String permission) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (permission == null || authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(permission::equals);
    }

    private static String requireClaim(String claim) {
        String value = jwt().getClaimAsString(claim);
        if (value == null || value.isBlank()) {
            throw IdentityClaimException.missing(claim);
        }
        return value;
    }

    private static Jwt jwt() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            return jwt;
        }
        throw new AuthenticationCredentialsNotFoundException(
                "No JWT-authenticated user in the security context");
    }
}
