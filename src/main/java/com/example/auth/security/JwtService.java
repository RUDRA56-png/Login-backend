package com.example.auth.security;

import com.example.auth.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    public record GeneratedToken(String token, String tokenId, LocalDateTime issuedAt,
                                 LocalDateTime expiresAt, long expiresInSeconds) {
    }

    private final SecretKey key;
    private final long expirationMinutes;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.expiration-minutes}") long expirationMinutes) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret must be at least 32 characters long");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.expirationMinutes = expirationMinutes;
    }

    public GeneratedToken generate(User user) {
        String tokenId = UUID.randomUUID().toString();
        Date issued = new Date();
        Date expires = new Date(issued.getTime() + expirationMinutes * 60_000L);

        String token = Jwts.builder()
                .id(tokenId)
                .subject(String.valueOf(user.getId()))
                .claim("email", user.getEmail())
                .issuedAt(issued)
                .expiration(expires)
                .signWith(key)
                .compact();

        ZoneId zone = ZoneId.systemDefault();
        return new GeneratedToken(token, tokenId,
                LocalDateTime.ofInstant(issued.toInstant(), zone),
                LocalDateTime.ofInstant(expires.toInstant(), zone),
                expirationMinutes * 60L);
    }

    /** Verifies signature + expiry. Throws io.jsonwebtoken.JwtException / IllegalArgumentException if invalid. */
    public Claims parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }
}
