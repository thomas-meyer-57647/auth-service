package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "RegistrationVerifyResponse", description = "Response payload returned after e-mail verification.")
public class RegistrationVerifyResponseDto {

    @Schema(description = "Identifier of the registration that was verified.", example = "reg_97f9d2c9-d5b6-4c3d-b4e9-33b6796d04f2", requiredMode = Schema.RequiredMode.REQUIRED)
    private String registrationId;

    @Schema(description = "Updated registration status.", example = "EMAIL_VERIFIED", requiredMode = Schema.RequiredMode.REQUIRED)
    private String status;

    @Schema(description = "Human readable confirmation message.", example = "E-mail address verified, activation can continue.", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String message;

    public RegistrationVerifyResponseDto() {
    }

    public RegistrationVerifyResponseDto(String registrationId, String status, String message) {
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
