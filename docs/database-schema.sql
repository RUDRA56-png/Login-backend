-- Reference schema (MySQL). The application creates these tables automatically via
-- spring.jpa.hibernate.ddl-auto=update, so you do NOT need to run this file manually.

CREATE TABLE users (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    full_name     VARCHAR(100) NOT NULL,
    email         VARCHAR(150) NOT NULL,
    mobile_number VARCHAR(10)  NOT NULL,
    password      VARCHAR(100) NOT NULL,           -- BCrypt hash
    created_at    DATETIME(6)  NOT NULL,
    updated_at    DATETIME(6)  NOT NULL,
    CONSTRAINT uk_users_email  UNIQUE (email),
    CONSTRAINT uk_users_mobile UNIQUE (mobile_number)
);

CREATE TABLE user_sessions (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT        NOT NULL,
    token_id    VARCHAR(64)   NOT NULL,            -- JWT "jti" claim
    jwt_token   VARCHAR(1000) NOT NULL,
    login_time  DATETIME(6)   NOT NULL,
    expiry_time DATETIME(6)   NOT NULL,
    active      BIT           NOT NULL,
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE INDEX idx_sessions_token_id (token_id),
    INDEX idx_sessions_user_id (user_id)
);

CREATE TABLE password_reset_otps (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id          BIGINT       NOT NULL,
    otp_hash         VARCHAR(100) NOT NULL,        -- BCrypt hash of the 6-digit OTP
    expiry_time      DATETIME(6)  NOT NULL,
    attempts         INT          NOT NULL,
    verified         BIT          NOT NULL,
    used             BIT          NOT NULL,
    reset_token_hash VARCHAR(64),                  -- SHA-256 of the one-time reset token
    created_at       DATETIME(6)  NOT NULL,
    CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_reset_user_id (user_id),
    INDEX idx_reset_token (reset_token_hash)
);
