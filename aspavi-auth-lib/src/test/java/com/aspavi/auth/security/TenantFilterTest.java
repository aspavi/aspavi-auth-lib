package com.aspavi.auth.security;

import com.aspavi.auth.tenant.TenantContext;
import com.aspavi.auth.tenant.TenantIssuers;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class TenantFilterTest {

    private static final String PATTERN = "https://kc.example.com/realms/rrhh-tenant-{tenant}";

    private final TenantFilter filter = new TenantFilter(
            TenantIssuers.of(Map.of("legacy", "https://old.example.com/realms/legacy"), PATTERN));
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/employees");
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final AtomicReference<String> tenantSeenByChain = new AtomicReference<>();
    private boolean chainCalled;
    private final FilterChain chain = (req, res) -> {
        chainCalled = true;
        tenantSeenByChain.set(TenantContext.getTenantId());
    };

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
    }

    @Test
    void setsTheTenantOfTheIssuingRealmWhenTheClaimMatches() throws Exception {
        authenticate("https://kc.example.com/realms/rrhh-tenant-acme", "acme");

        filter.doFilter(request, response, chain);

        assertThat(chainCalled).isTrue();
        assertThat(tenantSeenByChain).hasValue("acme");
        assertThat(TenantContext.getTenantId()).isNull();
    }

    @Test
    void takesTheTenantOfAMapIssuerFromTheMap() throws Exception {
        authenticate("https://old.example.com/realms/legacy", "legacy");

        filter.doFilter(request, response, chain);

        assertThat(tenantSeenByChain).hasValue("legacy");
    }

    @Test
    void rejectsAClaimThatDoesNotMatchTheIssuingRealm() throws Exception {
        authenticate("https://kc.example.com/realms/rrhh-tenant-acme", "test");

        filter.doFilter(request, response, chain);

        assertUnauthorized("Token tenant_id does not match the realm that issued it");
    }

    @Test
    void rejectsATokenWithoutTenantClaim() throws Exception {
        authenticate("https://kc.example.com/realms/rrhh-tenant-acme", null);

        filter.doFilter(request, response, chain);

        assertUnauthorized("Token has no tenant_id claim");
    }

    @Test
    void rejectsABlankTenantClaim() throws Exception {
        authenticate("https://kc.example.com/realms/rrhh-tenant-acme", " ");

        filter.doFilter(request, response, chain);

        assertUnauthorized("Token has no tenant_id claim");
    }

    @Test
    void rejectsATokenWhoseIssuerNamesNoTenant() throws Exception {
        authenticate("https://kc.example.com/realms/master", "master");

        filter.doFilter(request, response, chain);

        assertUnauthorized("Token issuer does not belong to any tenant");
    }

    @Test
    void rejectsATokenWithoutIssuer() throws Exception {
        authenticate(null, "acme");

        filter.doFilter(request, response, chain);

        assertUnauthorized("Token issuer does not belong to any tenant");
    }

    @Test
    void usesTheRealmNameOfAnIssuerTheDecoderDidNotCheck() throws Exception {
        authenticate("https://keycloak.test/realms/rrhh-tenant-acme", "acme");

        filter.doFilter(request, response, chain);

        assertThat(tenantSeenByChain).hasValue("acme");
    }

    @Test
    void theNoArgumentFilterOnlyKnowsTheRealmNameConvention() throws Exception {
        authenticate("https://keycloak.test/realms/rrhh-tenant-acme", "acme");

        new TenantFilter().doFilter(request, response, chain);

        assertThat(tenantSeenByChain).hasValue("acme");
    }

    @Test
    void letsRequestsWithoutJwtThroughWithoutTenant() throws Exception {
        filter.doFilter(request, response, chain);
        assertThat(chainCalled).isTrue();
        assertThat(tenantSeenByChain).hasNullValue();

        chainCalled = false;
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user", "pw", AuthorityUtils.NO_AUTHORITIES));
        filter.doFilter(request, response, chain);
        assertThat(chainCalled).isTrue();
        assertThat(tenantSeenByChain).hasNullValue();
    }

    @Test
    void escapesThePathInTheErrorBody() throws Exception {
        MockHttpServletRequest odd = new MockHttpServletRequest("GET", "/a\"b\\c");
        authenticate("https://kc.example.com/realms/rrhh-tenant-acme", "test");

        filter.doFilter(odd, response, chain);

        DocumentContext body = JsonPath.parse(response.getContentAsString());
        assertThat(body.read("$.path", String.class)).isEqualTo("/a\"b\\c");
    }

    private void assertUnauthorized(String message) throws Exception {
        assertThat(chainCalled).isFalse();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getHeader("WWW-Authenticate")).contains("invalid_token").contains(message);
        DocumentContext body = JsonPath.parse(response.getContentAsString());
        assertThat(body.read("$.status", Integer.class)).isEqualTo(401);
        assertThat(body.read("$.error", String.class)).isEqualTo("UNAUTHORIZED");
        assertThat(body.read("$.message", String.class)).isEqualTo(message);
        assertThat(body.read("$.path", String.class)).isEqualTo("/api/v1/employees");
        assertThat(LocalDateTime.parse(body.read("$.timestamp", String.class))).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(TenantContext.getTenantId()).isNull();
    }

    private static void authenticate(String issuer, String tenantId) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("user-1")
                .issuedAt(Instant.now());
        if (issuer != null) {
            builder.issuer(issuer);
        }
        if (tenantId != null) {
            builder.claim(AspaviClaims.TENANT_ID, tenantId);
        }
        Jwt jwt = builder.build();
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt, AuthorityUtils.NO_AUTHORITIES));
    }
}
