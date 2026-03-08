package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "PasswordChangeRequest", description = "Request payload to change password for an authenticated credential.")
public class PasswordChangeRequestDto {

    @Schema(description = "Current password of the credential.", example = "OldP@ssw0rd!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String currentPassword;

    @Schema(description = "New password to set.", example = "NewStr0ngP@ss!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(min = 8, max = 128)
    private String newPassword;

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
