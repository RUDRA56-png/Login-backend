package com.example.auth.controller;

import com.example.auth.dto.*;
import com.example.auth.security.AuthUser;
import com.example.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/logout")
    public LogoutResponse logout(@AuthenticationPrincipal AuthUser user) {
        return authService.logout(user);
    }

    @PostMapping("/forgot-password")
    public MessageResponse forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request);
        // Same response whether or not the account exists.
        return new MessageResponse("If the account exists, an OTP has been sent");
    }

    @PostMapping("/verify-otp")
    public VerifyOtpResponse verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        return authService.verifyOtp(request);
    }

    @PostMapping("/reset-password")
    public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return new MessageResponse("Password reset successful. Please log in with your new password");
    }

    @PutMapping("/change-password")
    public MessageResponse changePassword(@AuthenticationPrincipal AuthUser user,
                                          @Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(user, request);
        return new MessageResponse("Password changed successfully");
    }

    /** Example protected resource. */
    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal AuthUser user) {
        return authService.currentUser(user);
    }
}
