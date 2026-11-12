package com.aspavi.auth.tenant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantIssuersTest {

    private static final String PATTERN = "https://kc.example.com/realms/rrhh-tenant-{tenant}";

    @Test
    void patternGivesTheTenantOfAnyMatchingIssuer() {
        TenantIssuers issuers = TenantIssuers.of(Map.of(), PATTERN);

        assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-acme")).contains("acme");
        assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-new-client-2")).contains("new-client-2");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://evil.example.com/realms/rrhh-tenant-acme",
            "http://kc.example.com/realms/rrhh-tenant-acme",
            "https://kc.example.com/realms/master",
            "https://kc.example.com/realms/rrhh-tenant-",
            "https://kc.example.com/realms/rrhh-tenant-a",
            "https://kc.example.com/realms/rrhh-tenant-Acme",
            "https://kc.example.com/realms/rrhh-tenant-1acme",
            "https://kc.example.com/realms/rrhh-tenant-acme/",
            "https://kc.example.com/realms/rrhh-tenant-acme/../master",
            "https://kc.example.com/realms/rrhh-tenant-acme_x",
            "https://kc.example.com/realms/rrhh-tenant-abcdefghijklmnopqrstuvwxyz12345",
            "https://kc.example.com/realms/rrhh-tenant-acme\nx",
            "xhttps://kc.example.com/realms/rrhh-tenant-acme"
    })
    void patternRejectsIssuersThatDoNotFitExactly(String issuer) {
        TenantIssuers issuers = TenantIssuers.of(Map.of(), PATTERN);

        assertThat(issuers.tenantFor(issuer)).isEmpty();
    }

    @Test
    void patternIsLiteralExceptForThePlaceholder() {
        TenantIssuers issuers = TenantIssuers.of(Map.of(), "https://kc.example.com/realms/t.{tenant}");

        assertThat(issuers.tenantFor("https://kc.example.com/realms/t.acme")).contains("acme");
        assertThat(issuers.tenantFor("https://kc.example.com/realms/tXacme")).isEmpty();
    }

    @Test
    void tenantIdOfThirtyCharactersIsTheLongestAccepted() {
        TenantIssuers issuers = TenantIssuers.of(Map.of(), PATTERN);
        String thirty = "a" + "b".repeat(29);

        assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-" + thirty)).contains(thirty);
        assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-" + thirty + "c")).isEmpty();
    }

    @Test
    void mapMatchesExactlyAndWorksWithoutPattern() {
        TenantIssuers issuers = TenantIssuers.of(Map.of("test", "http://localhost:8180/realms/rrhh-tenant-test"), null);

        assertThat(issuers.tenantFor("http://localhost:8180/realms/rrhh-tenant-test")).contains("test");
        assertThat(issuers.tenantFor("http://localhost:8180/realms/rrhh-tenant-test/")).isEmpty();
        assertThat(issuers.tenantFor("http://localhost:8180/realms/rrhh-tenant-acme")).isEmpty();
        assertThat(issuers.tenantFor(null)).isEmpty();
        assertThat(issuers.issuerPattern()).isNull();
    }

    @Test
    void mapAndPatternCountTogether() {
        TenantIssuers issuers = TenantIssuers.of(Map.of("legacy", "https://old.example.com/realms/legacy"), PATTERN);

        assertThat(issuers.tenantFor("https://old.example.com/realms/legacy")).contains("legacy");
        assertThat(issuers.tenantFor("https://kc.example.com/realms/rrhh-tenant-acme")).contains("acme");
    }

    @Test
    void blankPatternMeansNoPattern() {
        assertThat(TenantIssuers.of(Map.of(), "  ").issuerPattern()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://kc.example.com/realms/rrhh-tenant-acme",
            "https://kc.example.com/realms/{tenant}-{tenant}"
    })
    void patternNeedsExactlyOnePlaceholder(String pattern) {
        assertThatThrownBy(() -> TenantIssuers.of(Map.of(), pattern))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("{tenant}");
    }

    @Test
    void realmNameConventionNamesTheTenantWhateverTheHost() {
        assertThat(TenantIssuers.tenantFromRealmName("https://keycloak.test/realms/rrhh-tenant-acme")).contains("acme");
        assertThat(TenantIssuers.tenantFromRealmName("http://dummy/realms/test")).isEmpty();
        assertThat(TenantIssuers.tenantFromRealmName("https://kc/realms/rrhh-tenant-Acme")).isEmpty();
        assertThat(TenantIssuers.tenantFromRealmName(null)).isEmpty();
    }

    @Test
    void validTenantIds() {
        assertThat(TenantIssuers.isValidTenantId("acme")).isTrue();
        assertThat(TenantIssuers.isValidTenantId("a1-b")).isTrue();
        assertThat(TenantIssuers.isValidTenantId("a")).isFalse();
        assertThat(TenantIssuers.isValidTenantId("-acme")).isFalse();
        assertThat(TenantIssuers.isValidTenantId(null)).isFalse();
    }
}
