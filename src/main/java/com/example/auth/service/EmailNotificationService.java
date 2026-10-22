package com.example.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Sends the OTP by email (active when app.mail.enabled=true).
 * SMS is not implemented: for a mobile-number destination the OTP is only logged.
 */
@Service
@ConditionalOnProperty(name = "app.mail.enabled", havingValue = "true")
public class EmailNotificationService implements NotificationService {

    private static final Logger log = LoggerFactory.getLogger(EmailNotificationService.class);

    private final JavaMailSender mailSender;
    private final String from;
    private final long expiryMinutes;

    public EmailNotificationService(JavaMailSender mailSender,
                                    @Value("${app.mail.from}") String from,
                                    @Value("${app.otp.expiry-minutes}") long expiryMinutes) {
        this.mailSender = mailSender;
        this.from = from;
        this.expiryMinutes = expiryMinutes;
    }

    @Override
    public void sendOtp(String destination, String otp) {
        if (!destination.contains("@")) {
            log.info("[DEV ONLY - SMS not configured] OTP for mobile {} is {}", destination, otp);
            return;
        }
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(from);
            message.setTo(destination);
            message.setSubject("Your password reset OTP");
            message.setText("Your OTP is " + otp + ".\n\nIt is valid for " + expiryMinutes
                    + " minutes. Do not share it with anyone.\nIf you did not request this, ignore this email.");
            mailSender.send(message);
            log.info("OTP email sent to {}", destination);
        } catch (Exception e) {
            // Do not fail the request: the API must answer the same way whether or not the account exists.
            log.error("Failed to send OTP email to {}: {}", destination, e.getMessage());
        }
    }
}
