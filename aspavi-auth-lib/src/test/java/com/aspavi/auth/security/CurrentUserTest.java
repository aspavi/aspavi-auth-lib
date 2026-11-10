package com.aspavi.auth.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CurrentUserTest {

    private static final UUID EMPLOYEE = UUID.fromString("7c9e6679-7425-40de-944b-e07fc1f90ae7");

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void readsIdentityFromTheJwt() {
        authenticate(claims -> {
            claims.put("sub", "kc-user-1");
            claims.put("tenant_id", "acme");
            claims.put("employee_id", EMPLOYEE.toString());
        });

        assertThat(CurrentUser.userId()).isEqualTo("kc-user-1");
        assertThat(CurrentUser.tenantId()).isEqualTo("acme");
        assertThat(CurrentUser.employeeId()).contains(EMPLOYEE);
        assertThat(CurrentUser.requireEmployeeId()).isEqualTo(EMPLOYEE);
    }

    @Test
    void employeeIdIsEmptyWhenClaimIsMissingOrBlank() {
        authenticate(claims -> {});
        assertThat(CurrentUser.employeeId()).isEmpty();

        authenticate(claims -> claims.put("employee_id", " "));
        assertThat(CurrentUser.employeeId()).isEmpty();
    }

    @Test
    void requireEmployeeIdThrowsAccessDeniedWhenClaimIsMissing() {
        authenticate(claims -> {});

        assertThatThrownBy(CurrentUser::requireEmployeeId)
                .isInstanceOf(IdentityClaimException.class)
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class)
                .satisfies(e -> assertThat(((IdentityClaimException) e).getClaim()).isEqualTo("employee_id"));
    }

    @Test
    void employeeIdThrowsAccessDeniedWhenClaimIsNotAUuid() {
        authenticate(claims -> claims.put("employee_id", "not-a-uuid"));
        assertThatThrownBy(CurrentUser::employeeId).isInstanceOf(IdentityClaimException.class);

        authenticate(claims -> claims.put("employee_id", "1-1-1-1-1"));
        assertThatThrownBy(CurrentUser::requireEmployeeId).isInstanceOf(IdentityClaimException.class);
    }

    @Test
    void tenantIdThrowsAccessDeniedWhenClaimIsMissing() {
        authenticate(claims -> {});

        assertThatThrownBy(CurrentUser::tenantId)
                .isInstanceOf(IdentityClaimException.class)
                .hasMessageContaining("tenant_id");
    }

    @Test
    void identityMethodsThrowUnauthenticatedWithoutAJwt() {
        assertThatThrownBy(CurrentUser::userId).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        assertThatThrownBy(CurrentUser::tenantId).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        assertThatThrownBy(CurrentUser::employeeId).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        assertThatThrownBy(CurrentUser::requireEmployeeId)
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);

        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "pwd"));
        assertThatThrownBy(CurrentUser::userId).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    @Test
    void hasPermissionChecksGrantedAuthorities() {
        Jwt jwt = jwt(claims -> {});
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("employee:read"))));

        assertThat(CurrentUser.hasPermission("employee:read")).isTrue();
        assertThat(CurrentUser.hasPermission("employee:write")).isFalse();
        assertThat(CurrentUser.hasPermission(null)).isFalse();
    }

    @Test
    void hasPermissionIsFalseWithoutAuthenticatedUser() {
        assertThat(CurrentUser.hasPermission("employee:read")).isFalse();

        TestingAuthenticationToken unauthenticated = new TestingAuthenticationToken("user", "pwd", "employee:read");
        unauthenticated.setAuthenticated(false);
        SecurityContextHolder.getContext().setAuthentication(unauthenticated);
        assertThat(CurrentUser.hasPermission("employee:read")).isFalse();
    }

    private static void authenticate(Consumer<Map<String, Object>> customizer) {
        Jwt jwt = jwt(customizer);
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }

    private static Jwt jwt(Consumer<Map<String, Object>> customizer) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("iss", "https://kc.example.com/realms/test")
                .claims(customizer::accept)
                .build();
    }
}
