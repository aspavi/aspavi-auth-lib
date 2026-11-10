package com.aspavi.auth.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Maps the Keycloak realm roles in {@code realm_access.roles} to granted authorities,
 * exactly as they appear in the token (no {@code ROLE_} or {@code SCOPE_} prefix).
 *
 * <p>Keycloak puts the user's <em>effective</em> realm roles in the token, so a composite
 * role arrives together with every atomic permission it contains
 * (e.g. {@code employee:read}). Services therefore check permissions with
 * {@code hasAuthority('employee:read')} and never need to know about composite roles.
 *
 * <p>Null-safe: a missing or malformed {@code realm_access} claim yields no authorities,
 * and non-string or blank entries are ignored.
 */
public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        if (!(jwt.getClaims().get(AspaviClaims.REALM_ACCESS) instanceof Map<?, ?> realmAccess)) {
            return List.of();
        }
        if (!(realmAccess.get(AspaviClaims.ROLES) instanceof Collection<?> roles)) {
            return List.of();
        }
        return roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(role -> !role.isBlank())
                .distinct()
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }
}
