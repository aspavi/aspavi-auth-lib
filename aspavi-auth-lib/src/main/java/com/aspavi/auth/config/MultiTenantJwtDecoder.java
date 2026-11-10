package com.aspavi.auth.config;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A composite {@link JwtDecoder} that selects the correct per-tenant decoder
 * based on the {@code iss} (issuer) claim found in the unverified JWT payload.
 *
 * <p>Decoders are created lazily and cached for reuse. Each tenant decoder is
 * configured from its Keycloak issuer URI via OIDC discovery.
 *
 * <p>The issuer is extracted from the raw token <em>before</em> signature verification
 * so we can route the token to the correct decoder. The actual cryptographic
 * validation is always delegated to {@link NimbusJwtDecoder}.
 */
public class MultiTenantJwtDecoder implements JwtDecoder {

    /** Pre-configured map of issuer URI → tenant id (from AuthProperties). */
    private final Map<String, String> issuerToTenant;

    /** Pre-configured map of tenant id → issuer URI (from AuthProperties). */
    private final Map<String, String> tenantToIssuer;

    /** Lazily-initialised decoders, keyed by issuer URI. */
    private final ConcurrentHashMap<String, JwtDecoder> decoderCache = new ConcurrentHashMap<>();

    public MultiTenantJwtDecoder(Map<String, String> tenants) {
        this.tenantToIssuer = Map.copyOf(tenants);
        Map<String, String> reverse = new ConcurrentHashMap<>();
        tenants.forEach((tenant, issuer) -> reverse.put(issuer, tenant));
        this.issuerToTenant = Map.copyOf(reverse);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        String issuer = extractIssuerUnchecked(token);
        if (issuer == null || !issuerToTenant.containsKey(issuer)) {
            throw new JwtException("Unknown or missing issuer in token: " + issuer);
        }
        return decoderCache
                .computeIfAbsent(issuer, this::buildDecoder)
                .decode(token);
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts the {@code iss} claim from the JWT payload without verifying the
     * signature. Uses standard library JSON parsing via a simple key scan to avoid
     * pulling in an extra JSON dependency.
     *
     * <p>Real signature verification is always performed by the per-tenant
     * {@link NimbusJwtDecoder}.
     */
    private String extractIssuerUnchecked(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }

            byte[] payloadBytes = Base64.getUrlDecoder().decode(padBase64(parts[1]));
            String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);

            // Locate the "iss" key and extract its string value.
            // Handles standard compact JWT payloads produced by Keycloak.
            int keyIdx = payloadJson.indexOf("\"iss\"");
            if (keyIdx == -1) {
                return null;
            }
            int colon = payloadJson.indexOf(':', keyIdx + 5);
            if (colon == -1) {
                return null;
            }
            // Skip optional whitespace after the colon
            int valueStart = colon + 1;
            while (valueStart < payloadJson.length() && payloadJson.charAt(valueStart) != '"') {
                valueStart++;
            }
            if (valueStart >= payloadJson.length()) {
                return null;
            }
            // valueStart points to the opening quote; find the closing one
            int contentStart = valueStart + 1;
            int contentEnd = payloadJson.indexOf('"', contentStart);
            if (contentEnd == -1) {
                return null;
            }
            return payloadJson.substring(contentStart, contentEnd);

        } catch (IllegalArgumentException e) {
            // Base64 decoding failed — malformed token
            return null;
        }
    }

    /**
     * Adds Base64 padding characters so that {@link Base64#getUrlDecoder()} can
     * decode JWT segments, which are unpadded by the JWT spec.
     */
    private String padBase64(String base64url) {
        return switch (base64url.length() % 4) {
            case 2 -> base64url + "==";
            case 3 -> base64url + "=";
            default -> base64url;
        };
    }

    private JwtDecoder buildDecoder(String issuerUri) {
        return NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
    }
}
