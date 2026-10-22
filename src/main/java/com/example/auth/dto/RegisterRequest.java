package com.example.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Full name is required")
        @Size(min = 3, max = 100, message = "Full name must be between 3 and 100 characters")
        String fullName,

        @NotBlank(message = "Email address is required")
        @Size(max = 150, message = "Email address must not exceed 150 characters")
        @Pattern(regexp = ValidationRules.EMAIL_REGEX, message = "Email address is not valid")
        String email,

        @NotBlank(message = "Mobile number is required")
        @Pattern(regexp = ValidationRules.MOBILE_REGEX, message = "Mobile number must contain exactly 10 digits")
        String mobileNumber,

        @NotBlank(message = "Password is required")
        @Pattern(regexp = ValidationRules.PASSWORD_REGEX, message = ValidationRules.PASSWORD_MESSAGE)
        String password,

        @NotBlank(message = "Confirm password is required")
        String confirmPassword) {
}
