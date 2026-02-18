package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "AcceptedResponse", description = "Neutral accepted response for async/security-sensitive flows.")
public class AcceptedResponseDto {

    @Schema(description = "Result message.", example = "If the account exists, further instructions were sent.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String message;

    public AcceptedResponseDto() {
    }

    public AcceptedResponseDto(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
