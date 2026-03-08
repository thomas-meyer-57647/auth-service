package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "SocialLoginRequest", description = "Payload used to start a social login flow.")
public class SocialLoginRequestDto {

    @Schema(description = "Social provider token (ID token / access token) that proves the user identity.", example = "ya29.a0AfH6SMCk...", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String socialToken;

    public String getSocialToken() {
        return socialToken;
    }

    public void setSocialToken(String socialToken) {
        this.socialToken = socialToken;
    }
}
