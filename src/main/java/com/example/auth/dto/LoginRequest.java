package com.example.auth.dto;

import jakarta.validation.constraints.NotBlank;

/** identifier = email address OR 10-digit mobile number. */
public record LoginRequest(
        @NotBlank(message = "Email or mobile number is required") String identifier,
        @NotBlank(message = "Password is required") String password) {
}
