package com.aspavi.auth.security;

import com.aspavi.auth.tenant.TenantContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Servlet filter that extracts the tenant identifier from the authenticated JWT
 * and stores it in {@link TenantContext} for the duration of the request.
 *
 * <p>The tenant id is read from the {@code tenant_id} claim of the JWT. If the
 * claim is absent the filter falls through without setting a tenant, which causes
 * Hibernate to use the {@code public} schema as a safe default.
 *
 * <p>Registered <em>after</em> {@code BearerTokenAuthenticationFilter} so that
 * the Security Context is already populated when this filter runs.
 */
public class TenantFilter extends OncePerRequestFilter {

    private static final String TENANT_CLAIM = AspaviClaims.TENANT_ID;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
                String tenantId = jwt.getClaimAsString(TENANT_CLAIM);
                if (tenantId != null && !tenantId.isBlank()) {
                    TenantContext.setTenantId(tenantId);
                }
            }

            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
}
