package com.aspavi.auth.security;

import com.aspavi.auth.tenant.TenantContext;
import com.aspavi.auth.tenant.TenantIssuers;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;

/**
 * Servlet filter that sets the tenant of the request in {@link TenantContext} from the
 * authenticated JWT, and clears it when the request ends.
 *
 * <p>The tenant comes from the realm that issued the token: the tenant of its {@code iss} in
 * {@code aspavi.auth.tenants} or {@code aspavi.auth.issuer-pattern}, or else the
 * {@code rrhh-tenant-<tenant>} realm name in the issuer (only tokens that the library's decoder
 * did not check get that far, e.g. test tokens). The {@code tenant_id} claim must be present and
 * equal to it. Otherwise the request ends here with 401 and the common error body
 * ({@code timestamp, status, error, message, path}).
 *
 * <p>Requests without a JWT (anonymous, public endpoints) go through without a tenant.
 *
 * <p>Registered <em>after</em> {@code BearerTokenAuthenticationFilter} so that
 * the Security Context is already populated when this filter runs.
 */
public class TenantFilter extends OncePerRequestFilter {

    private static final Log log = LogFactory.getLog(TenantFilter.class);

    private final TenantIssuers issuers;

    /** Only the {@code rrhh-tenant-<tenant>} realm-name convention; prefer the bean of the auto-configuration. */
    public TenantFilter() {
        this(TenantIssuers.none());
    }

    public TenantFilter(TenantIssuers issuers) {
        this.issuers = Objects.requireNonNull(issuers, "issuers");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
                String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
                Optional<String> issuerTenant = issuers.tenantFor(issuer)
                        .or(() -> TenantIssuers.tenantFromRealmName(issuer));
                if (issuerTenant.isEmpty()) {
                    reject(request, response, "Token issuer does not belong to any tenant");
                    return;
                }
                String claimTenant = jwt.getClaimAsString(AspaviClaims.TENANT_ID);
                if (claimTenant == null || claimTenant.isBlank()) {
                    reject(request, response, "Token has no tenant_id claim");
                    return;
                }
                if (!claimTenant.equals(issuerTenant.get())) {
                    reject(request, response, "Token tenant_id does not match the realm that issued it");
                    return;
                }
                TenantContext.setTenantId(claimTenant);
            }

            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private static void reject(HttpServletRequest request, HttpServletResponse response, String message)
            throws IOException {
        log.warn("Rejected token at '" + request.getRequestURI() + "': " + message);
        SecurityContextHolder.clearContext();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate",
                "Bearer error=\"invalid_token\", error_description=\"" + message + "\"");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        response.getWriter().write("{"
                + "\"timestamp\":\"" + LocalDateTime.now() + "\","
                + "\"status\":401,"
                + "\"error\":\"UNAUTHORIZED\","
                + "\"message\":" + json(message) + ","
                + "\"path\":" + json(request.getRequestURI())
                + "}");
    }

    private static String json(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
