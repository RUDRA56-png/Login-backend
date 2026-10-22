package com.example.auth.dto;

/** redirectUrl tells the client (web/mobile) where to send the user after logout. */
public record LogoutResponse(String message, String redirectUrl) {
}
