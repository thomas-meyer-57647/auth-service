package de.innologic.auth.web.dto;

import de.innologic.auth.domain.enums.RecoveryChannel;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Schema(name = "MfaRecoveryStartRequest", description = "Start MFA recovery and request a short-lived recovery token.")
public class MfaRecoveryStartRequestDto {

    @Schema(description = "Account e-mail address.", example = "user@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Email
    private String email;

    @Schema(description = "Delivery channel for recovery challenge.", example = "EMAIL", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull
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
