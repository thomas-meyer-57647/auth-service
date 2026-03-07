ALTER TABLE credentials
    CHANGE COLUMN email login_email VARCHAR(255) NOT NULL,
    CHANGE COLUMN user_status status VARCHAR(64) NOT NULL,
    CHANGE COLUMN failed_login_attempts failed_attempts INT NOT NULL DEFAULT 0,
    CHANGE COLUMN updated_at modified_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    ADD COLUMN user_id VARCHAR(64) NULL AFTER id;

ALTER TABLE mfa RENAME TO mfa_configs;

ALTER TABLE mfa_configs
    CHANGE COLUMN secret_encrypted totp_secret_encrypted VARCHAR(512) NULL,
    ADD COLUMN second_factor_type VARCHAR(32) NULL AFTER enabled,
    ADD COLUMN email_channel_enabled BOOLEAN NOT NULL DEFAULT TRUE AFTER second_factor_type,
    ADD COLUMN sms_channel_enabled BOOLEAN NOT NULL DEFAULT TRUE AFTER email_channel_enabled;

ALTER TABLE sessions RENAME TO refresh_sessions;

ALTER TABLE refresh_sessions
    ADD COLUMN sid VARCHAR(64) NOT NULL DEFAULT '' AFTER credential_id,
    ADD COLUMN user_id VARCHAR(64) NULL AFTER session_policy,
    ADD COLUMN tenant_id VARCHAR(64) NULL AFTER user_id,
    ADD COLUMN last_used_at DATETIME(6) NULL AFTER expires_at;

DROP INDEX idx_sessions_credential_id ON refresh_sessions;
DROP INDEX idx_sessions_expires_at ON refresh_sessions;
CREATE INDEX idx_refresh_sessions_credential_id ON refresh_sessions (credential_id);
CREATE INDEX idx_refresh_sessions_expires_at ON refresh_sessions (expires_at);

ALTER TABLE idempotency RENAME TO idempotency_records;
DROP INDEX idx_idempotency_expires_at ON idempotency_records;
CREATE INDEX idx_idempotency_records_expires_at ON idempotency_records (expires_at);

CREATE TABLE registration_processes (
    id BIGINT NOT NULL AUTO_INCREMENT,
    registration_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    status VARCHAR(64) NOT NULL,
    company_payload TEXT NULL,
    location_payload TEXT NULL,
    user_payload TEXT NULL,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    modified_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_registration_processes PRIMARY KEY (id),
    CONSTRAINT uk_registration_processes_registration_id UNIQUE (registration_id)
) ENGINE=InnoDB;

CREATE TABLE jwt_key_metadata (
    id BIGINT NOT NULL AUTO_INCREMENT,
    kid VARCHAR(128) NOT NULL,
    algorithm VARCHAR(32) NOT NULL,
    public_key TEXT NOT NULL,
    private_key_ref VARCHAR(256),
    status VARCHAR(32) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    valid_from DATETIME(6) NOT NULL,
    valid_until DATETIME(6) NOT NULL,
    CONSTRAINT pk_jwt_key_metadata PRIMARY KEY (id),
    CONSTRAINT uk_jwt_key_metadata_kid UNIQUE (kid)
) ENGINE=InnoDB;

ALTER TABLE refresh_sessions
    ADD CONSTRAINT uk_refresh_sessions_sid UNIQUE (sid);
