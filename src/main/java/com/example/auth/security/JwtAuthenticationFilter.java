package com.example.auth.security;

import com.example.auth.entity.UserSession;
import com.example.auth.repository.UserSessionRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Authenticates a request only if BOTH hold:
 *  1. the JWT signature/expiry is valid, and
 *  2. a matching ACTIVE session exists in the database.
 * Check (2) is what makes logout and password reset take effect immediately.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtService jwtService;
    private final UserSessionRepository sessionRepository;

    public JwtAuthenticationFilter(JwtService jwtService, UserSessionRepository sessionRepository) {
        this.jwtService = jwtService;
        this.sessionRepository = sessionRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = header.substring(7).trim();
            try {
                Claims claims = jwtService.parse(token);
                Optional<UserSession> session = sessionRepository.findByTokenIdAndActiveTrue(claims.getId());
                if (session.isPresent() && session.get().getExpiryTime().isAfter(LocalDateTime.now())) {
                    AuthUser principal = new AuthUser(Long.valueOf(claims.getSubject()),
                            claims.get("email", String.class), claims.getId());
                    var authentication = new UsernamePasswordAuthenticationToken(
                            principal, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (JwtException | IllegalArgumentException ex) {
                log.debug("Rejected JWT: {}", ex.getMessage());
            }
        }
        chain.doFilter(request, response);
    }
}
