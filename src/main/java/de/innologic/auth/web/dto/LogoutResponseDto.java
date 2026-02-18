package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "LogoutResponse", description = "Logout result.")
public class LogoutResponseDto {

    @Schema(description = "Result message.", example = "Logged out", requiredMode = Schema.RequiredMode.REQUIRED)
    private String message;

    public LogoutResponseDto() {
    }

    public LogoutResponseDto(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
