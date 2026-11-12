package com.aspavi.auth.config;

import com.aspavi.auth.tenant.TenantIssuers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The decoder against a local fake Keycloak with two tenant realms (alpha and beta), neither of
 * them listed anywhere: only the issuer pattern names them.
 */
class MultiTenantJwtDecoderTest {

    private static final String ALPHA = "rrhh-tenant-alpha";
    private static final String BETA = "rrhh-tenant-beta";
    private static final Duration TTL = Duration.ofMinutes(5);

    private FakeKeycloak keycloak;
    private MutableClock clock;

    @BeforeEach
    void setUp() throws IOException {
        keycloak = new FakeKeycloak().withRealm(ALPHA).withRealm(BETA);
        clock = new MutableClock(Instant.parse("2026-11-12T10:00:00Z"));
    }

    @AfterEach
    void tearDown() {
        keycloak.close();
    }

    @Test
    void acceptsTokensOfAnyRealmThatMatchesThePattern() {
        MultiTenantJwtDecoder decoder = patternDecoder(10);

        Jwt alpha = decoder.decode(keycloak.token(ALPHA, "alpha"));
        Jwt beta = decoder.decode(keycloak.token(BETA, "beta"));

        assertThat(alpha.getIssuer()).hasToString(keycloak.issuer(ALPHA));
        assertThat(alpha.getClaimAsString("tenant_id")).isEqualTo("alpha");
        assertThat(beta.getIssuer()).hasToString(keycloak.issuer(BETA));
    }

    @Test
    void discoversEachIssuerOnceAndReusesItsDecoder() {
        MultiTenantJwtDecoder decoder = patternDecoder(10);

        decoder.decode(keycloak.token(ALPHA, "alpha"));
        decoder.decode(keycloak.token(ALPHA, "alpha"));
        decoder.decode(keycloak.token(ALPHA, "alpha"));

        assertThat(keycloak.discoveryRequests(ALPHA)).isEqualTo(1);
        assertThat(keycloak.requests()).hasSize(2); // discovery + JWKS
    }

    @Test
    void rejectsATokenSignedWithTheKeyOfAnotherRealm() {
        MultiTenantJwtDecoder decoder = patternDecoder(10);
        String forged = keycloak.token(keycloak.issuer(ALPHA), "alpha", BETA);

        assertThatThrownBy(() -> decoder.decode(forged)).isInstanceOf(BadJwtException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://evil.example.com/realms/rrhh-tenant-alpha",
            "/realms/master",
            "/realms/rrhh-tenant-Alpha",
            "/realms/rrhh-tenant-a",
            "/realms/rrhh-tenant-alpha/../master",
            "/realms/rrhh-tenant-alpha/"
    })
    void anIssuerOutsideThePatternMakesNoRequest(String iss) {
        MultiTenantJwtDecoder decoder = patternDecoder(10);
        String issuer = iss.startsWith("/") ? keycloak.baseUrl() + iss : iss;

        assertThatThrownBy(() -> decoder.decode(keycloak.token(issuer, "alpha", ALPHA)))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("Unknown or missing issuer");
        assertThat(keycloak.requests()).isEmpty();
    }

    @Test
    void aTokenWithoutIssuerOrThatIsNotAJwtMakesNoRequest() {
        MultiTenantJwtDecoder decoder = patternDecoder(10);

        assertThatThrownBy(() -> decoder.decode(keycloak.token(null, "alpha", ALPHA)))
                .isInstanceOf(BadJwtException.class);
        assertThatThrownBy(() -> decoder.decode("not-a-jwt")).isInstanceOf(BadJwtException.class);
        assertThat(keycloak.requests()).isEmpty();
    }

    @Test
    void aRealmThatDoesNotExistIsRememberedUntilTheTtlExpires() {
        MultiTenantJwtDecoder decoder = patternDecoder(10);
        String ghost = keycloak.token(keycloak.issuer("rrhh-tenant-ghost"), "ghost", ALPHA);

        assertThatThrownBy(() -> decoder.decode(ghost)).isInstanceOf(BadJwtException.class);
        assertThat(keycloak.discoveryRequests("rrhh-tenant-ghost")).isEqualTo(1);

        for (int i = 0; i < 5; i++) {
            assertThatThrownBy(() -> decoder.decode(ghost)).isInstanceOf(BadJwtException.class);
        }
        clock.advance(TTL.minusSeconds(1));
        assertThatThrownBy(() -> decoder.decode(ghost)).isInstanceOf(BadJwtException.class);
        assertThat(keycloak.discoveryRequests("rrhh-tenant-ghost")).isEqualTo(1);

        clock.advance(Duration.ofSeconds(1));
        assertThatThrownBy(() -> decoder.decode(ghost)).isInstanceOf(BadJwtException.class);
        assertThat(keycloak.discoveryRequests("rrhh-tenant-ghost")).isEqualTo(2);
    }

    @Test
    void aTenantCreatedAfterItsRealmWasRejectedIsAcceptedOnceTheTtlExpires() {
        MultiTenantJwtDecoder decoder = patternDecoder(10);
        String early = keycloak.token(keycloak.issuer("rrhh-tenant-gamma"), "gamma", ALPHA);
        assertThatThrownBy(() -> decoder.decode(early)).isInstanceOf(BadJwtException.class);

        keycloak.withRealm("rrhh-tenant-gamma");
        String token = keycloak.token("rrhh-tenant-gamma", "gamma");
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(BadJwtException.class);

        clock.advance(TTL);
        assertThat(decoder.decode(token).getClaimAsString("tenant_id")).isEqualTo("gamma");
    }

    @Test
    void aTransientDiscoveryFailureIsNotRemembered() {
        keycloak.failingDiscovery(ALPHA, 1);
        MultiTenantJwtDecoder decoder = patternDecoder(10);
        String token = keycloak.token(ALPHA, "alpha");

        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtException.class)
                .isNotInstanceOf(BadJwtException.class);

        assertThat(decoder.decode(token).getClaimAsString("tenant_id")).isEqualTo("alpha");
        assertThat(keycloak.discoveryRequests(ALPHA)).isEqualTo(2);
    }

    @Test
    void aDiscoveryDocumentOfAnotherIssuerIsRejectedAndRemembered() {
        keycloak.withDiscoveryIssuer(ALPHA, keycloak.issuer(BETA));
        MultiTenantJwtDecoder decoder = patternDecoder(10);
        String token = keycloak.token(ALPHA, "alpha");

        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(BadJwtException.class);
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(BadJwtException.class);
        assertThat(keycloak.discoveryRequests(ALPHA)).isEqualTo(1);
    }

    @Test
    void theDecoderCacheIsBounded() {
        MultiTenantJwtDecoder decoder = patternDecoder(1);

        decoder.decode(keycloak.token(ALPHA, "alpha"));
        decoder.decode(keycloak.token(BETA, "beta"));
        decoder.decode(keycloak.token(ALPHA, "alpha"));

        assertThat(keycloak.discoveryRequests(ALPHA)).isEqualTo(2);
        assertThat(keycloak.discoveryRequests(BETA)).isEqualTo(1);
    }

    @Test
    void theFixedMapStillWorksWithoutPattern() {
        MultiTenantJwtDecoder decoder = decoder(TenantIssuers.of(Map.of("alpha", keycloak.issuer(ALPHA)), null), 10);

        assertThat(decoder.decode(keycloak.token(ALPHA, "alpha")).getClaimAsString("tenant_id")).isEqualTo("alpha");
        keycloak.clearRequests();
        assertThatThrownBy(() -> decoder.decode(keycloak.token(BETA, "beta"))).isInstanceOf(BadJwtException.class);
        assertThat(keycloak.requests()).isEmpty();
    }

    @Test
    void mapAndPatternCountTogether() {
        keycloak.withRealm("legacy");
        MultiTenantJwtDecoder decoder = decoder(
                TenantIssuers.of(Map.of("legacy", keycloak.issuer("legacy")), keycloak.issuerPattern()), 10);

        assertThat(decoder.decode(keycloak.token("legacy", "legacy")).getClaimAsString("tenant_id")).isEqualTo("legacy");
        assertThat(decoder.decode(keycloak.token(BETA, "beta")).getClaimAsString("tenant_id")).isEqualTo("beta");
    }

    @Test
    void theMapConstructorKeepsWorking() {
        MultiTenantJwtDecoder decoder = new MultiTenantJwtDecoder(Map.of("alpha", keycloak.issuer(ALPHA)));

        assertThat(decoder.decode(keycloak.token(ALPHA, "alpha")).getSubject()).isEqualTo("user-1");
    }

    @Test
    void rejectsInvalidCacheSettings() {
        TenantIssuers issuers = TenantIssuers.none();
        assertThatThrownBy(() -> new MultiTenantJwtDecoder(issuers, 0, TTL)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MultiTenantJwtDecoder(issuers, 1, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private MultiTenantJwtDecoder patternDecoder(int maxDecoders) {
        return decoder(TenantIssuers.of(Map.of(), keycloak.issuerPattern()), maxDecoders);
    }

    private MultiTenantJwtDecoder decoder(TenantIssuers issuers, int maxDecoders) {
        return new MultiTenantJwtDecoder(issuers, maxDecoders, TTL, new IssuerDiscovery(Duration.ofSeconds(2)), clock);
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
