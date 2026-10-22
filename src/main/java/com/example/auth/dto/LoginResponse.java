package com.example.auth.dto;

import java.time.LocalDateTime;

public record LoginResponse(String accessToken, String tokenType, long expiresInSeconds,
                            LocalDateTime expiresAt, UserResponse user) {
}
