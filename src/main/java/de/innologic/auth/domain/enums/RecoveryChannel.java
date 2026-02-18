package de.innologic.auth.domain.enums;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "MFA recovery delivery channel.", example = "EMAIL")
public enum RecoveryChannel {
    EMAIL,
    SMS
}
