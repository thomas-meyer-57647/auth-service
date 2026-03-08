package de.innologic.auth.web.dto;

import de.innologic.auth.domain.enums.RecoveryChannel;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "PasswordForgotRequest", description = "Request to initiate password reset.")
public class PasswordForgotRequestDto {

    @Schema(description = "Account e-mail address.", example = "user@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Email
    private String email;

    @Schema(description = "Preferred recovery delivery channel.", example = "EMAIL")
    private RecoveryChannel channel;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public RecoveryChannel getChannel() {
        return channel;
    }

    public void setChannel(RecoveryChannel channel) {
        this.channel = channel;
    }
}
