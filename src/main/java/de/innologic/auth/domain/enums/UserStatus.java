package de.innologic.auth.domain.enums;

public enum UserStatus {
    PENDING_EMAIL_VERIFICATION,
    PENDING_MFA_ENROLLMENT,
    ACTIVATION_IN_PROGRESS,
    ACTIVE,
    DISABLED,
    LOCKED
}
