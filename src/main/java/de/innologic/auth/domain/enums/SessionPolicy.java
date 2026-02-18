package de.innologic.auth.domain.enums;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Refresh-session policy.",
        example = "HOURS_24"
)
public enum SessionPolicy {
    HOURS_24,
    MONTHS_3
}
