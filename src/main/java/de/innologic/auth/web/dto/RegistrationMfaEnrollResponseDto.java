package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "RegistrationMfaEnrollResponse", description = "Response payload with TOTP setup data.")
public class RegistrationMfaEnrollResponseDto {

    @Schema(description = "Registration identifier that produced the enrollment.", example = "reg_97f9d2c9-d5b6-4c3d-b4e9-33b6796d04f2", requiredMode = Schema.RequiredMode.REQUIRED)
    private String registrationId;

    @Schema(description = "Secret that must be entered into the Authenticator app.", example = "JBSWY3DPEHPK3PXP", requiredMode = Schema.RequiredMode.REQUIRED)
    private String secret;

    @Schema(description = "otpauth URI that can be scanned by the Authenticator app.", example = "otpauth://totp/auth-service:starter@example.com?secret=JBSWY3DPEHPK3PXP&issuer=auth-service", requiredMode = Schema.RequiredMode.REQUIRED)
    private String otpauthUri;

    @Schema(description = "Enrollment status.", example = "MFA_ENROLLMENT_PREPARED", requiredMode = Schema.RequiredMode.REQUIRED)
    private String status;

    public RegistrationMfaEnrollResponseDto() {
    }

    public RegistrationMfaEnrollResponseDto(String registrationId, String secret, String otpauthUri, String status) {
        this.registrationId = registrationId;
        this.secret = secret;
        this.otpauthUri = otpauthUri;
        this.status = status;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getOtpauthUri() {
        return otpauthUri;
    }

    public void setOtpauthUri(String otpauthUri) {
        this.otpauthUri = otpauthUri;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
