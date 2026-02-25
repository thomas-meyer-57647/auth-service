package de.innologic.auth.web.error;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Application-wide error codes.")
public enum ErrorCode {
    VALIDATION_ERROR,
    INVALID_CREDENTIALS,
    INTERNAL_API_KEY_INVALID,
    USER_LOCKED,
    USER_DISABLED,
    MFA_REQUIRED,
    TOTP_INVALID,
    REFRESH_INVALID,
    TOKEN_INVALID,
    TOKEN_EXPIRED,
    SESSION_REVOKED,
    SESSION_EXPIRED,
    IDEMPOTENCY_CONFLICT,
    RATE_LIMITED,
    FORBIDDEN,
    INTERNAL_ERROR
}
