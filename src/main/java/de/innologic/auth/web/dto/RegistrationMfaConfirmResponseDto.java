package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "RegistrationMfaConfirmResponse", description = "Response payload when TOTP confirmation succeeds.")
public class RegistrationMfaConfirmResponseDto {

    @Schema(description = "Registration identifier that was confirmed.", example = "reg_97f9d2c9-d5b6-4c3d-b4e9-33b6796d04f2", requiredMode = Schema.RequiredMode.REQUIRED)
    private String registrationId;

    @Schema(description = "Current registration status.", example = "ACTIVE", requiredMode = Schema.RequiredMode.REQUIRED)
    private String status;

    @Schema(description = "Optional informational message.", example = "MFA confirmed; activation completed.")
    private String message;

    public RegistrationMfaConfirmResponseDto() {
    }

    public RegistrationMfaConfirmResponseDto(String registrationId, String status, String message) {
        this.registrationId = registrationId;
        this.status = status;
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

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
