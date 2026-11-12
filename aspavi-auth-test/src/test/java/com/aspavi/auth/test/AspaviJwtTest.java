package com.aspavi.auth.test;

import com.aspavi.auth.security.CurrentUser;
import com.aspavi.auth.security.IdentityClaimException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.TestSecurityContextHolder;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AspaviJwtTest {

    private static final UUID EMPLOYEE = UUID.fromString("7c9e6679-7425-40de-944b-e07fc1f90ae7");

    @AfterEach
    void clearContext() {
        TestSecurityContextHolder.clearContext();
        SecurityContextHolder.clearContext();
    }

    @Test
    void buildsKeycloakLikeTokenWithDefaults() {
        Jwt jwt = AspaviJwt.withPermissions("employee:read").toJwt();

        assertThat(jwt.getSubject()).isEqualTo(AspaviJwt.DEFAULT_SUBJECT);
        assertThat(jwt.getClaimAsString("tenant_id")).isEqualTo(AspaviJwt.DEFAULT_TENANT_ID);
        assertThat(jwt.getIssuer()).hasToString(AspaviJwt.DEFAULT_ISSUER);
        assertThat(jwt.getClaimAsMap("realm_access")).isEqualTo(Map.of("roles", List.of("employee:read")));
        assertThat(jwt.hasClaim("employee_id")).isFalse();
    }

    @Test
    void appliesCustomClaims() {
        Jwt jwt = AspaviJwt.withPermissions()
                .tenantId("acme")
                .subject("kc-user-1")
                .employeeId(EMPLOYEE)
                .claim("preferred_username", "jdoe")
                .toJwt();

        assertThat(jwt.getSubject()).isEqualTo("kc-user-1");
        assertThat(jwt.getClaimAsString("tenant_id")).isEqualTo("acme");
        assertThat(jwt.getIssuer()).hasToString("https://keycloak.test/realms/rrhh-tenant-acme");
        assertThat(jwt.getClaimAsString("employee_id")).isEqualTo(EMPLOYEE.toString());
        assertThat(jwt.getClaimAsString("preferred_username")).isEqualTo("jdoe");
        assertThat(jwt.getClaimAsMap("realm_access")).isEqualTo(Map.of("roles", List.of()));
    }

    @Test
    void issuerCanBeSetApartFromTheTenant() {
        Jwt jwt = AspaviJwt.withPermissions().issuer("https://kc.example.com/realms/rrhh-tenant-test").tenantId("acme").toJwt();

        assertThat(jwt.getIssuer()).hasToString("https://kc.example.com/realms/rrhh-tenant-test");
        assertThat(jwt.getClaimAsString("tenant_id")).isEqualTo("acme");
    }

    @Test
    void authoritiesMatchTheProductionConverter() {
        JwtAuthenticationToken authentication =
                AspaviJwt.withPermissions("employee:read", "employee:write").toAuthentication();

        assertThat(authorities(authentication)).containsExactly("employee:read", "employee:write");
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getName()).isEqualTo(AspaviJwt.DEFAULT_SUBJECT);
    }

    @Test
    void authenticateFeedsCurrentUser() {
        AspaviJwt.withPermissions("employee:read").subject("kc-user-1").authenticate();

        assertThat(CurrentUser.userId()).isEqualTo("kc-user-1");
        assertThat(CurrentUser.tenantId()).isEqualTo(AspaviJwt.DEFAULT_TENANT_ID);
        assertThat(CurrentUser.employeeId()).isEmpty();
        assertThatThrownBy(CurrentUser::requireEmployeeId).isInstanceOf(IdentityClaimException.class);
    }

    @Test
    void satisfiesHasAuthorityInMethodSecurity() {
        new ApplicationContextRunner().withUserConfiguration(MethodSecurityConfig.class).run(context -> {
            EmployeeReader reader = context.getBean(EmployeeReader.class);

            AspaviJwt.withPermissions("employee:read").authenticate();
            assertThat(reader.read()).isEqualTo("ok");

            AspaviJwt.withPermissions("employee:write").authenticate();
            assertThatThrownBy(reader::read).isInstanceOf(AccessDeniedException.class);
        });
    }

    private static List<String> authorities(Authentication authentication) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableMethodSecurity
    static class MethodSecurityConfig {
        @Bean
        EmployeeReader employeeReader() {
            return new EmployeeReader();
        }
    }

    static class EmployeeReader {
        @PreAuthorize("hasAuthority('employee:read')")
        public String read() {
            return "ok";
        }
    }
}
