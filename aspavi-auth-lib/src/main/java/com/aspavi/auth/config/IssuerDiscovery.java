package com.aspavi.auth.config;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.Map;
import java.util.function.Function;

/**
 * Builds the decoder of one issuer: one OpenID discovery request to
 * {@code <issuer>/.well-known/openid-configuration}, then a {@link NimbusJwtDecoder} on its
 * {@code jwks_uri} that also requires {@code iss} to equal the issuer.
 *
 * <p>A realm that does not exist (404/410), or a discovery document that does not describe this
 * issuer, throws {@link UnknownIssuerException}, which the caller remembers for a while. Anything
 * else (connection refused, timeout, 5xx) is a plain {@link JwtException} and is retried on the
 * next request.
 */
class IssuerDiscovery implements Function<String, JwtDecoder> {

    static final String WELL_KNOWN = "/.well-known/openid-configuration";

    private final HttpClient httpClient;
    private final Duration timeout;

    IssuerDiscovery(Duration timeout) {
        this.timeout = timeout;
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public JwtDecoder apply(String issuer) {
        String jwkSetUri = discoverJwkSetUri(issuer);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }

    private String discoverJwkSetUri(String issuer) {
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(URI.create(issuer + WELL_KNOWN))
                    .timeout(timeout)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
        } catch (IllegalArgumentException e) {
            throw new UnknownIssuerException("issuer is not a valid URI", e);
        }

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new JwtException("Could not reach the token issuer for discovery", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JwtException("Interrupted during issuer discovery", e);
        }

        int status = response.statusCode();
        if (status == 404 || status == 410) {
            throw new UnknownIssuerException("realm not found (discovery answered " + status + ")");
        }
        if (status != 200) {
            throw new JwtException("Issuer discovery answered " + status);
        }

        Map<String, Object> metadata;
        try {
            metadata = JSONObjectUtils.parse(response.body());
        } catch (ParseException e) {
            throw new UnknownIssuerException("discovery document is not JSON", e);
        }
        if (!issuer.equals(metadata.get("issuer"))) {
            throw new UnknownIssuerException("discovery document describes another issuer");
        }
        if (!(metadata.get("jwks_uri") instanceof String jwkSetUri) || jwkSetUri.isBlank()) {
            throw new UnknownIssuerException("discovery document has no jwks_uri");
        }
        return jwkSetUri;
    }

    /** The issuer does not exist or is not a valid OpenID provider: worth remembering. */
    static class UnknownIssuerException extends RuntimeException {

        UnknownIssuerException(String message) {
            super(message);
        }

        UnknownIssuerException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
