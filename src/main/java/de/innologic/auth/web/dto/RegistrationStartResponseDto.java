package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(name = "RegistrationStartResponse", description = "Response payload returned when a registration is started.")
public class RegistrationStartResponseDto {

    @Schema(description = "Identifier that tracks the registration process.", example = "reg_97f9d2c9-d5b6-4c3d-b4e9-33b6796d04f2", requiredMode = Schema.RequiredMode.REQUIRED)
    private String registrationId;

    @Schema(description = "Current status of the registration process.", example = "PENDING_EMAIL_VERIFICATION", requiredMode = Schema.RequiredMode.REQUIRED)
    private String status;

    @Schema(description = "Point in time when the registration expires.", example = "2026-03-09T13:00:00Z", requiredMode = Schema.RequiredMode.REQUIRED)
    private Instant expiresAt;

    @Schema(description = "Human readable summary of the result.", example = "Registration initiated; verification email has been queued.", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String message;

    public RegistrationStartResponseDto() {
    }

    public RegistrationStartResponseDto(String registrationId, String status, Instant expiresAt, String message) {
        this.registrationId = registrationId;
        this.status = status;
        this.expiresAt = expiresAt;
        this.message = message;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
