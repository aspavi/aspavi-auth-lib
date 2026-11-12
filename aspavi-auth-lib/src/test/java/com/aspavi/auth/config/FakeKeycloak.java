package com.aspavi.auth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A local HTTP server that answers like Keycloak for OpenID discovery and JWKS, with one RSA key per
 * realm, and records every request. Unknown realms get 404 {@code {"error":"Realm does not exist"}}.
 */
final class FakeKeycloak implements AutoCloseable {

    private static final Pattern PATH = Pattern.compile("^/realms/([^/]+)(/.*)$");

    private final HttpServer server;
    private final Map<String, RSAKey> realms = new ConcurrentHashMap<>();
    private final Map<String, String> discoveryIssuerOverride = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> failuresToServe = new ConcurrentHashMap<>();
    private final List<String> requests = new CopyOnWriteArrayList<>();

    FakeKeycloak() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    String issuer(String realm) {
        return baseUrl() + "/realms/" + realm;
    }

    String issuerPattern() {
        return baseUrl() + "/realms/rrhh-tenant-{tenant}";
    }

    FakeKeycloak withRealm(String realm) {
        try {
            realms.put(realm, new RSAKeyGenerator(2048).keyID(realm + "-key").generate());
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /** The discovery document of this realm will name another issuer. */
    FakeKeycloak withDiscoveryIssuer(String realm, String issuer) {
        discoveryIssuerOverride.put(realm, issuer);
        return this;
    }

    /** The next {@code count} discovery requests of this realm answer 503. */
    FakeKeycloak failingDiscovery(String realm, int count) {
        failuresToServe.put(realm, new AtomicInteger(count));
        return this;
    }

    /** A token of {@code realm} with {@code iss} = that realm's issuer, signed with its key. */
    String token(String realm, String tenantId) {
        return token(issuer(realm), tenantId, realm);
    }

    /** A token with any {@code iss}, signed with the key of {@code signingRealm}. */
    String token(String iss, String tenantId, String signingRealm) {
        RSAKey key = realms.get(signingRealm);
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject("user-1")
                .issueTime(java.util.Date.from(now))
                .expirationTime(java.util.Date.from(now.plusSeconds(300)));
        if (iss != null) {
            claims.issuer(iss);
        }
        if (tenantId != null) {
            claims.claim("tenant_id", tenantId);
        }
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).type(JOSEObjectType.JWT).build(),
                    claims.build());
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    List<String> requests() {
        return List.copyOf(requests);
    }

    long discoveryRequests(String realm) {
        return requests.stream().filter(r -> r.equals("/realms/" + realm + IssuerDiscovery.WELL_KNOWN)).count();
    }

    void clearRequests() {
        requests.clear();
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        requests.add(path);
        Matcher matcher = PATH.matcher(path);
        if (!matcher.matches() || !realms.containsKey(matcher.group(1))) {
            respond(exchange, 404, "{\"error\":\"Realm does not exist\"}");
            return;
        }
        String realm = matcher.group(1);
        String rest = matcher.group(2);
        if (rest.equals(IssuerDiscovery.WELL_KNOWN)) {
            AtomicInteger failures = failuresToServe.get(realm);
            if (failures != null && failures.getAndDecrement() > 0) {
                respond(exchange, 503, "{\"error\":\"unavailable\"}");
                return;
            }
            String issuer = discoveryIssuerOverride.getOrDefault(realm, issuer(realm));
            respond(exchange, 200, "{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\""
                    + issuer(realm) + "/protocol/openid-connect/certs\"}");
        } else if (rest.equals("/protocol/openid-connect/certs")) {
            respond(exchange, 200, new JWKSet(realms.get(realm).toPublicJWK()).toString());
        } else {
            respond(exchange, 404, "{}");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
