package com.aspavi.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakRealmRoleConverterTest {

    private final KeycloakRealmRoleConverter converter = new KeycloakRealmRoleConverter();

    @Test
    void mapsRealmRolesAsIsWithoutPrefix() {
        Jwt jwt = jwt(claims -> claims.put("realm_access",
                Map.of("roles", List.of("employee:read", "employee:write", "ADMIN_RRHH"))));

        assertThat(authorities(jwt)).containsExactly("employee:read", "employee:write", "ADMIN_RRHH");
    }

    @Test
    void returnsNoAuthoritiesWhenRealmAccessIsMissing() {
        assertThat(authorities(jwt(claims -> {}))).isEmpty();
    }

    @Test
    void returnsNoAuthoritiesWhenRealmAccessIsNotAMap() {
        assertThat(authorities(jwt(claims -> claims.put("realm_access", "employee:read")))).isEmpty();
    }

    @Test
    void returnsNoAuthoritiesWhenRolesIsMissing() {
        assertThat(authorities(jwt(claims -> claims.put("realm_access", Map.of())))).isEmpty();
    }

    @Test
    void returnsNoAuthoritiesWhenRolesIsNotACollection() {
        assertThat(authorities(jwt(claims -> claims.put("realm_access",
                Map.of("roles", "employee:read"))))).isEmpty();
    }

    @Test
    void ignoresNullBlankNonStringAndDuplicateEntries() {
        Jwt jwt = jwt(claims -> claims.put("realm_access", Map.of("roles",
                Arrays.asList("employee:read", null, "", "  ", 42, Map.of("x", 1), "employee:read"))));

        assertThat(authorities(jwt)).containsExactly("employee:read");
    }

    @Test
    void ignoresTopLevelRolesClaim() {
        Jwt jwt = jwt(claims -> claims.put("roles", List.of("employee:read")));

        assertThat(authorities(jwt)).isEmpty();
    }

    private List<String> authorities(Jwt jwt) {
        return converter.convert(jwt).stream().map(GrantedAuthority::getAuthority).toList();
    }

    private static Jwt jwt(Consumer<Map<String, Object>> customizer) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user-1");
        customizer.accept(claims);
        return Jwt.withTokenValue("token").header("alg", "none").claims(c -> c.putAll(claims)).build();
    }
}
