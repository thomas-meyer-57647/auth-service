package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "PasswordResetRequest", description = "Request to reset password using reset token.")
public class PasswordResetRequestDto {

    @Schema(description = "Opaque reset token from password-forgot flow.", example = "prt_8RP_8dL4xH5nS3jg1L9FQw", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String token;

    @Schema(description = "New plain password.", example = "N3wP@ssw0rd!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(min = 8, max = 128)
    private String newPassword;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
