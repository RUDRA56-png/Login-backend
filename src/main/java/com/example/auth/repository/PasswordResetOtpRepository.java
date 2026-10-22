package com.example.auth.repository;

import com.example.auth.entity.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {
    Optional<PasswordResetOtp> findFirstByUserIdAndUsedFalseOrderByIdDesc(Long userId);
    Optional<PasswordResetOtp> findByResetTokenHash(String resetTokenHash);
    void deleteByUserId(Long userId);
}
