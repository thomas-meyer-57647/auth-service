package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "AccessTokenResponse", description = "Bearer access token response.")
public class AccessTokenResponseDto {

    @Schema(description = "JWT access token.", example = "eyJraWQiOiJkZXYtcnNhLWtleS0xIiwiYWxnIjoiUlMyNTYifQ...", requiredMode = Schema.RequiredMode.REQUIRED)
    private String accessToken;

    @Schema(description = "Token type.", example = "Bearer", requiredMode = Schema.RequiredMode.REQUIRED)
    private String tokenType;

    @Schema(description = "Access token lifetime in seconds.", example = "900", requiredMode = Schema.RequiredMode.REQUIRED)
    private long expiresIn;

    public AccessTokenResponseDto() {
    }

    public AccessTokenResponseDto(String accessToken, String tokenType, long expiresIn) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }
}
