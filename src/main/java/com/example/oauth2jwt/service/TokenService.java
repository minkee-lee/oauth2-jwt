package com.example.oauth2jwt.service;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    @Value("${auth.token.expire-time}")
    private Long expireTime;

    @Value("${auth.token.issuer}")
    private String issuer;

    private final JWKSource jwkSource;

    public TokenDto generateToken(Long userId) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwsHeader.Builder headerBuilder = JwsHeader.with(SignatureAlgorithm.RS256);
        JwtClaimsSet.Builder claimBuilder = JwtClaimsSet.builder();

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(expireTime, ChronoUnit.MINUTES);

        // TODO find user info
        String username = String.valueOf(userId);

        claimBuilder.issuer(issuer)
                .subject(username)
                .audience(List.of("auth"))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt);

        JwsHeader header = headerBuilder.build();
        TokenUser tokenUser = TokenUser.builder()
                .username(username)
                .userId(userId)
                .build();
        JwtClaimsSet claims = claimBuilder
                .claim("user", tokenUser)
                .build();

        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(header, claims));
        return TokenDto.builder()
                .tokenValue(jwt.getTokenValue())
                .subject(username)
                .issuedAt(LocalDateTime.ofInstant(issuedAt, ZoneOffset.UTC))
                .expiresAt(LocalDateTime.ofInstant(expiresAt, ZoneOffset.UTC))
                .issuer(issuer)
                .build();
    }

    public String getJwks() {
        List<JWK> jwks = null;
        try {
            jwks = jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        } catch (KeySourceException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Get JWKS error");
        }
        return new JWKSet(jwks).toString();
    }
}
