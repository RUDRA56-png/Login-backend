package com.example.auth.service;

/** Abstraction for delivering OTPs. Swap the implementation for a real email/SMS provider. */
public interface NotificationService {
    void sendOtp(String destination, String otp);
}
