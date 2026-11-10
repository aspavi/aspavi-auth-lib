package com.aspavi.auth.security;

import org.springframework.security.access.AccessDeniedException;

/**
 * Thrown by {@link CurrentUser} when the authenticated token lacks an identity claim the
 * caller requires (e.g. {@code employee_id}) or the claim is malformed.
 *
 * <p>It extends {@link AccessDeniedException}, so Spring Security's
 * {@code ExceptionTranslationFilter} answers {@code 403 Forbidden} on its own. A service
 * with a catch-all {@code @ExceptionHandler(Exception.class)} must map this exception
 * (or {@code AccessDeniedException}) to 403 explicitly.
 */
public class IdentityClaimException extends AccessDeniedException {

    private final String claim;

    private IdentityClaimException(String claim, String message) {
        super(message);
        this.claim = claim;
    }

    public static IdentityClaimException missing(String claim) {
        return new IdentityClaimException(claim, "Token has no '" + claim + "' claim");
    }

    public static IdentityClaimException invalid(String claim, String value) {
        return new IdentityClaimException(claim,
                "Token claim '" + claim + "' has an invalid value: '" + value + "'");
    }

    /** Name of the claim that was missing or invalid. */
    public String getClaim() {
        return claim;
    }
}
