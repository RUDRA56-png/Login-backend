package com.example.auth.service;

import com.example.auth.dto.*;
import com.example.auth.entity.PasswordResetOtp;
import com.example.auth.entity.User;
import com.example.auth.entity.UserSession;
import com.example.auth.exception.*;
import com.example.auth.repository.PasswordResetOtpRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.repository.UserSessionRepository;
import com.example.auth.security.AuthUser;
import com.example.auth.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final PasswordResetOtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final NotificationService notificationService;

    private final long otpExpiryMinutes;
    private final int otpMaxAttempts;
    private final long resetTokenExpiryMinutes;

    private final SecureRandom secureRandom = new SecureRandom();
    /** Used so a login for an unknown account costs the same time as a wrong password (anti-enumeration). */
    private final String dummyHash;

    public AuthService(UserRepository userRepository,
                       UserSessionRepository sessionRepository,
                       PasswordResetOtpRepository otpRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       NotificationService notificationService,
                       @Value("${app.otp.expiry-minutes}") long otpExpiryMinutes,
                       @Value("${app.otp.max-attempts}") int otpMaxAttempts,
                       @Value("${app.reset-token.expiry-minutes}") long resetTokenExpiryMinutes) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.otpRepository = otpRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.notificationService = notificationService;
        this.otpExpiryMinutes = otpExpiryMinutes;
        this.otpMaxAttempts = otpMaxAttempts;
        this.resetTokenExpiryMinutes = resetTokenExpiryMinutes;
        this.dummyHash = passwordEncoder.encode("dummy-password-for-timing");
    }

    // ------------------------------------------------------------------ Register
    @Transactional
    public UserResponse register(RegisterRequest request) {
        requirePasswordsMatch(request.password(), request.confirmPassword());

        String email = request.email().trim().toLowerCase();
        String mobile = request.mobileNumber().trim();

        if (userRepository.existsByEmail(email)) {
            throw new DuplicateResourceException("Email address is already registered");
        }
        if (userRepository.existsByMobileNumber(mobile)) {
            throw new DuplicateResourceException("Mobile number is already registered");
        }

        User user = new User();
        user.setFullName(request.fullName().trim());
        user.setEmail(email);
        user.setMobileNumber(mobile);
        user.setPassword(passwordEncoder.encode(request.password()));
        return UserResponse.from(userRepository.save(user));
    }

    // ------------------------------------------------------------------ Login
    @Transactional
    public LoginResponse login(LoginRequest request) {
        Optional<User> found = findByIdentifier(request.identifier());

        String hash = found.map(User::getPassword).orElse(dummyHash);
        boolean passwordOk = passwordEncoder.matches(request.password(), hash);
        if (found.isEmpty() || !passwordOk) {
            throw new InvalidCredentialsException();   // same response for both cases
        }

        User user = found.get();
        JwtService.GeneratedToken generated = jwtService.generate(user);

        UserSession session = new UserSession();
        session.setUser(user);
        session.setTokenId(generated.tokenId());
        session.setJwtToken(generated.token());
        session.setLoginTime(generated.issuedAt());
        session.setExpiryTime(generated.expiresAt());
        session.setActive(true);
        sessionRepository.save(session);

        return new LoginResponse(generated.token(), "Bearer", generated.expiresInSeconds(),
                generated.expiresAt(), UserResponse.from(user));
    }

    // ------------------------------------------------------------------ Logout
    @Transactional
    public LogoutResponse logout(AuthUser authUser) {
        sessionRepository.findByTokenIdAndActiveTrue(authUser.tokenId()).ifPresent(s -> s.setActive(false));
        return new LogoutResponse("Logged out successfully", "/login");
    }

    // ------------------------------------------------------------------ Forgot password
    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        String identifier = request.identifier().trim();
        // Silent when the account does not exist, so callers cannot discover registered users.
        findByIdentifier(identifier).ifPresent(user -> {
            otpRepository.deleteByUserId(user.getId());   // only the newest OTP is ever valid

            String otp = String.format("%06d", secureRandom.nextInt(1_000_000));
            PasswordResetOtp record = new PasswordResetOtp();
            record.setUser(user);
            record.setOtpHash(passwordEncoder.encode(otp));
            record.setExpiryTime(LocalDateTime.now().plusMinutes(otpExpiryMinutes));
            otpRepository.save(record);

            String destination = identifier.contains("@") ? user.getEmail() : user.getMobileNumber();
            notificationService.sendOtp(destination, otp);
        });
    }

    // ------------------------------------------------------------------ Verify OTP
    // noRollbackFor: the failed-attempt counter must be saved even though we throw.
    @Transactional(noRollbackFor = InvalidOtpException.class)
    public VerifyOtpResponse verifyOtp(VerifyOtpRequest request) {
        User user = findByIdentifier(request.identifier()).orElseThrow(InvalidOtpException::new);
        PasswordResetOtp record = otpRepository.findFirstByUserIdAndUsedFalseOrderByIdDesc(user.getId())
                .orElseThrow(InvalidOtpException::new);

        if (record.isVerified()
                || record.getExpiryTime().isBefore(LocalDateTime.now())
                || record.getAttempts() >= otpMaxAttempts) {
            throw new InvalidOtpException();
        }

        if (!passwordEncoder.matches(request.otp(), record.getOtpHash())) {
            record.setAttempts(record.getAttempts() + 1);
            otpRepository.save(record);
            throw new InvalidOtpException();
        }

        byte[] raw = new byte[32];
        secureRandom.nextBytes(raw);
        String resetToken = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        record.setVerified(true);
        record.setResetTokenHash(sha256(resetToken));
        record.setExpiryTime(LocalDateTime.now().plusMinutes(resetTokenExpiryMinutes));
        otpRepository.save(record);

        return new VerifyOtpResponse("OTP verified. Use the reset token to set a new password.", resetToken);
    }

    // ------------------------------------------------------------------ Reset password
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        requirePasswordsMatch(request.newPassword(), request.confirmPassword());

        PasswordResetOtp record = otpRepository.findByResetTokenHash(sha256(request.resetToken()))
                .orElseThrow(() -> new BadRequestException("Invalid or expired reset token"));
        if (!record.isVerified() || record.isUsed() || record.getExpiryTime().isBefore(LocalDateTime.now())) {
            throw new BadRequestException("Invalid or expired reset token");
        }

        User user = record.getUser();
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        record.setUsed(true);
        otpRepository.save(record);

        sessionRepository.deactivateAllByUserId(user.getId());   // business rule: reset kills all sessions
    }

    // ------------------------------------------------------------------ Change password
    @Transactional
    public void changePassword(AuthUser authUser, ChangePasswordRequest request) {
        requirePasswordsMatch(request.newPassword(), request.confirmPassword());

        User user = userRepository.findById(authUser.userId()).orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new BadRequestException("Current password is incorrect");
        }
        if (passwordEncoder.matches(request.newPassword(), user.getPassword())) {
            throw new BadRequestException("New password must be different from the current password");
        }

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        // Keep the current session, sign out every other device.
        sessionRepository.deactivateOthers(user.getId(), authUser.tokenId());
    }

    // ------------------------------------------------------------------ Current user
    @Transactional(readOnly = true)
    public UserResponse currentUser(AuthUser authUser) {
        return userRepository.findById(authUser.userId())
                .map(UserResponse::from)
                .orElseThrow(InvalidCredentialsException::new);
    }

    // ------------------------------------------------------------------ helpers
    private Optional<User> findByIdentifier(String identifier) {
        String id = identifier.trim();
        return id.contains("@") ? userRepository.findByEmail(id.toLowerCase())
                                : userRepository.findByMobileNumber(id);
    }

    private void requirePasswordsMatch(String password, String confirm) {
        if (!password.equals(confirm)) {
            throw new BadRequestException("Confirm password must match the password");
        }
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
