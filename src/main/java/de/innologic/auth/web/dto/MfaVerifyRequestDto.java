package de.innologic.auth.web.dto;

import de.innologic.auth.domain.enums.SessionPolicy;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@Schema(name = "MfaVerifyRequest", description = "MFA verification payload for completing login and creating a session.")
public class MfaVerifyRequestDto {

    @Schema(description = "Transaction ID returned by /login.", example = "ltx_1fbe4b0c4dbb4a8d85f7037f0f5c4ad8", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String loginTransactionId;

    @Schema(description = "Time-based one-time password from authenticator app.", example = "123456", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Pattern(regexp = "^\\d{6}$")
    private String totpCode;

    @Schema(description = "Requested refresh session policy.", requiredMode = Schema.RequiredMode.REQUIRED, example = "HOURS_24")
    @NotNull
    private SessionPolicy sessionPolicy;

    public String getLoginTransactionId() {
        return loginTransactionId;
    }

    public void setLoginTransactionId(String loginTransactionId) {
        this.loginTransactionId = loginTransactionId;
    }

    public String getTotpCode() {
        return totpCode;
    }

    public void setTotpCode(String totpCode) {
        this.totpCode = totpCode;
    }

    public SessionPolicy getSessionPolicy() {
        return sessionPolicy;
    }

    public void setSessionPolicy(SessionPolicy sessionPolicy) {
        this.sessionPolicy = sessionPolicy;
    }
}
