package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "RegistrationMfaConfirmRequest", description = "Payload to confirm TOTP enrollment.")
public class RegistrationMfaConfirmRequestDto {

    @Schema(description = "Registration identifier for which enrollment was started.", example = "reg_97f9d2c9-d5b6-4c3d-b4e9-33b6796d04f2", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String registrationId;

    @Schema(description = "Current TOTP code displayed in the Authenticator app.", example = "123456", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(min = 6, max = 6)
    private String totpCode;

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getTotpCode() {
        return totpCode;
    }

    public void setTotpCode(String totpCode) {
        this.totpCode = totpCode;
    }
}
