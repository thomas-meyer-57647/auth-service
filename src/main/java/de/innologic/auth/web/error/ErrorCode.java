package de.innologic.auth.web.error;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Application-wide error codes.")
public enum ErrorCode {
    @Schema(description = "Request validation failed (missing/invalid fields).")
    VALIDATION_ERROR,
    @Schema(description = "Local credentials are invalid.")
    INVALID_CREDENTIALS,
    @Schema(description = "Access token is invalid.")
    TOKEN_INVALID,
    @Schema(description = "Access token has expired.")
    TOKEN_EXPIRED,
    @Schema(description = "Provided TOTP code is not valid.")
    TOTP_INVALID,
    @Schema(description = "Social authentication against Google/Facebook failed.")
    SOCIAL_AUTH_FAILED,
    @Schema(description = "User's email address is not verified.")
    EMAIL_NOT_VERIFIED,
    @Schema(description = "MFA is not enrolled for the credential.")
    MFA_NOT_ENROLLED,
    @Schema(description = "MFA is required for the current operation.")
    MFA_REQUIRED,
    @Schema(description = "Tenant identifier in header or token does not match.")
    TENANT_MISMATCH,
    @Schema(description = "Required scope is missing in the token.")
    SCOPE_MISSING,
    @Schema(description = "Access denied due to missing permissions.")
    ACCESS_DENIED,
    @Schema(description = "Rate limit exceeded for the endpoint/client.")
    RATE_LIMITED,
    @Schema(description = "Idempotency key used with a different payload.")
    IDEMPOTENCY_CONFLICT,
    @Schema(description = "E-mail address already exists for another user.")
    DUPLICATE_EMAIL,
    @Schema(description = "Social identity is already linked to another user.")
    SOCIAL_IDENTITY_ALREADY_LINKED,
    @Schema(description = "E-mail already used by a different provider.")
    EMAIL_ALREADY_USED_BY_OTHER_PROVIDER,
    @Schema(description = "Requested registration process was not found.")
    REGISTRATION_NOT_FOUND,
    @Schema(description = "Registration process has expired.")
    REGISTRATION_EXPIRED,
    @Schema(description = "The downstream user service is unavailable.")
    DOWNSTREAM_USER_UNAVAILABLE,
    @Schema(description = "The downstream company service is unavailable.")
    DOWNSTREAM_COMPANY_UNAVAILABLE,
    @Schema(description = "The downstream IAM service is unavailable.")
    DOWNSTREAM_IAM_UNAVAILABLE,
    @Schema(description = "The social provider (Google/Facebook) is unavailable.")
    SOCIAL_PROVIDER_UNAVAILABLE,
    @Schema(description = "Refresh token is invalid.")
    REFRESH_INVALID,
    @Schema(description = "Refresh session was revoked.")
    SESSION_REVOKED,
    @Schema(description = "Refresh session has expired.")
    SESSION_EXPIRED,
    @Schema(description = "Internal API key does not match the configured value.")
    INTERNAL_API_KEY_INVALID,
    @Schema(description = "Unexpected server error.")
    INTERNAL_ERROR
}
