package com.spring.jwt.security.service;

import com.spring.jwt.security.config.JwtConfig;
import com.spring.jwt.security.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtConfig jwtConfig;
    private final TokenRepository tokenRepository;

    public String generateToken(String subject) {
        return issueToken(subject, Map.of());
    }

    public String generateToken(String subject, String... scopes) {
        return issueToken(subject, Map.of("scopes", scopes));
    }

    public String generateToken(String subject, List<String> scopes) {
        return issueToken(subject, Map.of("scopes", scopes));
    }

    public String getSubject(String token) {
        return extractClaims(token).getSubject();
    }

    public Date getExpiration(String token) {
        return extractClaims(token).getExpiration();
    }

    private String issueToken(String subject, Map<String, Object> claims) {
        return Jwts.builder()
                .header()
                .type(jwtConfig.getType())
                .and()
                .id(UUID.randomUUID().toString())
                .issuer(jwtConfig.getIssuer())
                .claims(claims)
                .subject(subject)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(
                        TimeUnit.MINUTES.toMillis(jwtConfig.getExpirationTimeInMinutes())
                )))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isValidToken(String token, String username) {
        String subject = getSubject(token);
        return subject.equals(username) && !isTokenExpired(token) && isUserNotLoggedOutWithExistingToken(token);
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isUserNotLoggedOutWithExistingToken(String token) {
        return tokenRepository.findByAccessToken(token)
                .map(t -> !t.isUserLoggedOut())
                .orElse(false);
    }

    private SecretKey getSignInKey() {
        byte[] decodedKey = Base64.getDecoder().decode(jwtConfig.getSecretKey());
        return Keys.hmacShaKeyFor(decodedKey);
    }

    private boolean isTokenExpired(String token) {
        Date today = Date.from(Instant.now());
        return extractClaims(token).getExpiration().before(today);
    }
}
