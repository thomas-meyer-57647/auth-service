package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "MfaRecoveryConfirmRequest", description = "Confirm MFA recovery with a valid recovery token.")
public class MfaRecoveryConfirmRequestDto {

    @Schema(description = "Opaque recovery token from /mfa/recovery/start.", example = "mrt_G6x9Qf1S9xVw5iH2mQh7Dw", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
