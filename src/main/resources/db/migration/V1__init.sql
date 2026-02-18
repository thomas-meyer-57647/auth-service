CREATE TABLE credentials (
    id BIGINT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NULL,
    user_status VARCHAR(64) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME(6) NULL,
    last_login_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_credentials PRIMARY KEY (id),
    CONSTRAINT uk_credentials_email UNIQUE (email)
) ENGINE=InnoDB;

CREATE TABLE identities (
    id BIGINT NOT NULL AUTO_INCREMENT,
    credential_id BIGINT NOT NULL,
    provider VARCHAR(32) NOT NULL,
    provider_subject VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_identities PRIMARY KEY (id),
    CONSTRAINT uk_identities_provider_subject UNIQUE (provider, provider_subject),
    CONSTRAINT fk_identities_credential FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_identities_credential_id ON identities (credential_id);

CREATE TABLE mfa (
    id BIGINT NOT NULL AUTO_INCREMENT,
    credential_id BIGINT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    secret_encrypted VARCHAR(512) NULL,
    recovery_channel VARCHAR(16) NULL,
    phone_number VARCHAR(32) NULL,
    enrolled_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_mfa PRIMARY KEY (id),
    CONSTRAINT uk_mfa_credential_id UNIQUE (credential_id),
    CONSTRAINT fk_mfa_credential FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE sessions (
    id BIGINT NOT NULL AUTO_INCREMENT,
    credential_id BIGINT NOT NULL,
    session_policy VARCHAR(32) NOT NULL,
    refresh_token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(64) NULL,
    user_agent VARCHAR(512) NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_sessions PRIMARY KEY (id),
    CONSTRAINT uk_sessions_refresh_token_hash UNIQUE (refresh_token_hash),
    CONSTRAINT fk_sessions_credential FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_sessions_credential_id ON sessions (credential_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE verification_tokens (
    id BIGINT NOT NULL AUTO_INCREMENT,
    credential_id BIGINT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_verification_tokens PRIMARY KEY (id),
    CONSTRAINT uk_verification_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_verification_tokens_credential FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_verification_tokens_credential_id ON verification_tokens (credential_id);
CREATE INDEX idx_verification_tokens_expires_at ON verification_tokens (expires_at);

CREATE TABLE password_reset_tokens (
    id BIGINT NOT NULL AUTO_INCREMENT,
    credential_id BIGINT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_password_reset_tokens PRIMARY KEY (id),
    CONSTRAINT uk_password_reset_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_password_reset_tokens_credential FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_password_reset_tokens_credential_id ON password_reset_tokens (credential_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);

CREATE TABLE mfa_recovery_tokens (
    id BIGINT NOT NULL AUTO_INCREMENT,
    credential_id BIGINT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    consumed_at DATETIME(6) NULL,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_mfa_recovery_tokens PRIMARY KEY (id),
    CONSTRAINT uk_mfa_recovery_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_mfa_recovery_tokens_credential FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_mfa_recovery_tokens_credential_id ON mfa_recovery_tokens (credential_id);
CREATE INDEX idx_mfa_recovery_tokens_expires_at ON mfa_recovery_tokens (expires_at);

CREATE TABLE idempotency (
    id BIGINT NOT NULL AUTO_INCREMENT,
    idempotency_key VARCHAR(128) NOT NULL,
    request_hash VARCHAR(128) NOT NULL,
    response_status INT NULL,
    response_body TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    CONSTRAINT pk_idempotency PRIMARY KEY (id),
    CONSTRAINT uk_idempotency_key UNIQUE (idempotency_key)
) ENGINE=InnoDB;

CREATE INDEX idx_idempotency_expires_at ON idempotency (expires_at);
