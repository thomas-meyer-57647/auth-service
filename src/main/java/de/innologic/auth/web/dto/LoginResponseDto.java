package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "LoginResponse", description = "Response containing the MFA login transaction identifier.")
public class LoginResponseDto {

    @Schema(description = "Temporary transaction identifier used for MFA verification step.", example = "ltx_1fbe4b0c4dbb4a8d85f7037f0f5c4ad8", requiredMode = Schema.RequiredMode.REQUIRED)
    private String loginTransactionId;

    public LoginResponseDto() {
    }

    public LoginResponseDto(String loginTransactionId) {
        this.loginTransactionId = loginTransactionId;
    }

    public String getLoginTransactionId() {
        return loginTransactionId;
    }

    public void setLoginTransactionId(String loginTransactionId) {
        this.loginTransactionId = loginTransactionId;
    }
}
