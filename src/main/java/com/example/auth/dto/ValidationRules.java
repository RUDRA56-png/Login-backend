package com.example.auth.dto;

/** Central place for validation patterns so every DTO uses identical rules. */
public final class ValidationRules {
    private ValidationRules() {}

    public static final String EMAIL_REGEX = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    public static final String MOBILE_REGEX = "^\\d{10}$";
    /** min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character */
    public static final String PASSWORD_REGEX =
            "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}$";
    public static final String PASSWORD_MESSAGE =
            "Password must be at least 8 characters and contain an uppercase letter, "
                    + "a lowercase letter, a digit and a special character";
}
