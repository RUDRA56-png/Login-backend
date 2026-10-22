package com.example.auth.security;

/** The authenticated principal placed in the SecurityContext for each request. */
public record AuthUser(Long userId, String email, String tokenId) {
}
