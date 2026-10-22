package com.example.auth.dto;

import com.example.auth.entity.User;
import java.time.LocalDateTime;

public record UserResponse(Long id, String fullName, String email, String mobileNumber, LocalDateTime createdAt) {
    public static UserResponse from(User u) {
        return new UserResponse(u.getId(), u.getFullName(), u.getEmail(), u.getMobileNumber(), u.getCreatedAt());
    }
}
