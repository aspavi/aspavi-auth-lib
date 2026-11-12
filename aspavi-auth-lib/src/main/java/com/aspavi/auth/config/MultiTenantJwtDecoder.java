package com.aspavi.auth.config;

import com.aspavi.auth.config.IssuerDiscovery.UnknownIssuerException;
import com.aspavi.auth.tenant.TenantIssuers;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * A {@link JwtDecoder} for many Keycloak realms, one per tenant.
 *
 * <p>The {@code iss} claim is read from the token <em>without</em> verifying it, only to choose the
 * decoder: an issuer that is neither in {@code aspavi.auth.tenants} nor matches
 * {@code aspavi.auth.issuer-pattern} is rejected with no network request. For an accepted issuer,
 * the decoder is built on first use (OpenID discovery of that issuer, then its JWKS), and it checks
 * the signature with that realm's keys and requires {@code iss} to equal the issuer.
 *
 * <p>Built decoders are kept in an LRU cache of bounded size. An issuer whose realm does not exist
 * is remembered for {@code unknownIssuerTtl}, so a made-up {@code iss} that fits the pattern does not
 * reach Keycloak on every request. Errors that may be transient (Keycloak unreachable, 5xx) are not
 * remembered.
 */
public class MultiTenantJwtDecoder implements JwtDecoder {

    static final int DEFAULT_MAX_DECODERS = 100;
    static final Duration DEFAULT_UNKNOWN_ISSUER_TTL = Duration.ofMinutes(5);
    static final Duration DISCOVERY_TIMEOUT = Duration.ofSeconds(5);
    /** Bound of the unknown-issuer cache, so that random issuers cannot grow it without limit. */
    static final int MAX_UNKNOWN_ISSUERS = 1_000;

    private static final Log log = LogFactory.getLog(MultiTenantJwtDecoder.class);

    private final TenantIssuers issuers;
    private final Function<String, JwtDecoder> decoderFactory;
    private final Clock clock;
    private final Duration unknownIssuerTtl;
    private final Object lock = new Object();
    private final Map<String, JwtDecoder> decoders;
    private final Map<String, Instant> unknownIssuers;

    /** Fixed tenant → issuer map, default cache settings. */
    public MultiTenantJwtDecoder(Map<String, String> tenants) {
        this(TenantIssuers.of(tenants, null), DEFAULT_MAX_DECODERS, DEFAULT_UNKNOWN_ISSUER_TTL);
    }

    public MultiTenantJwtDecoder(TenantIssuers issuers, int maxDecoders, Duration unknownIssuerTtl) {
        this(issuers, maxDecoders, unknownIssuerTtl, new IssuerDiscovery(DISCOVERY_TIMEOUT), Clock.systemUTC());
    }

    MultiTenantJwtDecoder(TenantIssuers issuers,
                          int maxDecoders,
                          Duration unknownIssuerTtl,
                          Function<String, JwtDecoder> decoderFactory,
                          Clock clock) {
        if (maxDecoders < 1) {
            throw new IllegalArgumentException("aspavi.auth.issuer-cache.max-size must be at least 1");
        }
        if (unknownIssuerTtl == null || unknownIssuerTtl.isNegative()) {
            throw new IllegalArgumentException("aspavi.auth.issuer-cache.unknown-issuer-ttl must not be negative");
        }
        this.issuers = Objects.requireNonNull(issuers, "issuers");
        this.decoderFactory = Objects.requireNonNull(decoderFactory, "decoderFactory");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.unknownIssuerTtl = unknownIssuerTtl;
        this.decoders = lruMap(maxDecoders, true);
        this.unknownIssuers = lruMap(MAX_UNKNOWN_ISSUERS, false);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        String issuer = readIssuerUnverified(token);
        if (issuers.tenantFor(issuer).isEmpty()) {
            throw new BadJwtException("Unknown or missing issuer in token");
        }
        return decoderFor(issuer).decode(token);
    }

    private JwtDecoder decoderFor(String issuer) {
        synchronized (lock) {
            JwtDecoder cached = decoders.get(issuer);
            if (cached != null) {
                return cached;
            }
            Instant rejectedUntil = unknownIssuers.get(issuer);
            if (rejectedUntil != null) {
                if (clock.instant().isBefore(rejectedUntil)) {
                    throw new BadJwtException("Unknown issuer: realm not found");
                }
                unknownIssuers.remove(issuer);
            }
        }

        // Outside the lock: discovery is a network call. Two first requests for the same issuer
        // may both discover it; the first decoder stored wins.
        JwtDecoder created;
        try {
            created = decoderFactory.apply(issuer);
        } catch (UnknownIssuerException e) {
            synchronized (lock) {
                unknownIssuers.put(issuer, clock.instant().plus(unknownIssuerTtl));
            }
            log.warn("Rejecting tokens of issuer " + printable(issuer) + " for " + unknownIssuerTtl + ": " + e.getMessage());
            throw new BadJwtException("Unknown issuer: " + e.getMessage(), e);
        }

        synchronized (lock) {
            JwtDecoder raced = decoders.putIfAbsent(issuer, created);
            return raced != null ? raced : created;
        }
    }

    /**
     * Reads {@code iss} without checking the signature. Its only use is to pick a decoder; the
     * decoder then verifies the signature with the keys of that issuer.
     */
    private static String readIssuerUnverified(String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            return claims == null ? null : claims.getIssuer();
        } catch (ParseException | RuntimeException e) {
            throw new BadJwtException("Malformed token", e);
        }
    }

    /** For logs: the issuer comes from an unverified token, so keep it short and on one line. */
    private static String printable(String issuer) {
        String oneLine = issuer.replaceAll("\\p{Cntrl}", "?");
        return oneLine.length() > 200 ? oneLine.substring(0, 200) + "..." : oneLine;
    }

    private static <V> Map<String, V> lruMap(int maxSize, boolean accessOrder) {
        return new LinkedHashMap<>(16, 0.75f, accessOrder) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, V> eldest) {
                return size() > maxSize;
            }
        };
    }
}
