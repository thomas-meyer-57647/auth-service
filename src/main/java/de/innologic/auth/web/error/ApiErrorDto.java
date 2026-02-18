package de.innologic.auth.web.error;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(name = "ApiError", description = "Standard API error response.")
public class ApiErrorDto {

    @Schema(description = "Timestamp when the error was generated.", example = "2026-02-18T12:34:56Z", requiredMode = Schema.RequiredMode.REQUIRED)
    private Instant timestamp;

    @Schema(description = "HTTP status code.", example = "400", requiredMode = Schema.RequiredMode.REQUIRED)
    private int status;

    @Schema(description = "Application error code.", example = "INVALID_CREDENTIALS", requiredMode = Schema.RequiredMode.REQUIRED)
    private ErrorCode code;

    @Schema(description = "Human-readable message.", example = "E-mail or password is invalid.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String message;

    @Schema(description = "Request path.", example = "/api/v1/auth/login", requiredMode = Schema.RequiredMode.REQUIRED)
    private String path;

    public ApiErrorDto() {
    }

    public ApiErrorDto(Instant timestamp, int status, ErrorCode code, String message, String path) {
        this.timestamp = timestamp;
        this.status = status;
        this.code = code;
        this.message = message;
        this.path = path;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public ErrorCode getCode() {
        return code;
    }

    public void setCode(ErrorCode code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }
}
