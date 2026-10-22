package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/** Deliberately generic: never reveals whether the account or the password was wrong. */
public class InvalidCredentialsException extends AppException {
    public InvalidCredentialsException() {
        super(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }
}
