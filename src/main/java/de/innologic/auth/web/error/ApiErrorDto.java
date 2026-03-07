package de.innologic.auth.web.error;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(name = "ApiError", description = "Standard API error response.")
public class ApiErrorDto {

    @Schema(description = "Timestamp when the error was generated.", example = "2026-02-18T12:34:56Z", requiredMode = Schema.RequiredMode.REQUIRED)
    private Instant timestamp;

    @Schema(description = "HTTP status code.", example = "400", requiredMode = Schema.RequiredMode.REQUIRED)
    private int status;

    @Schema(description = "Application error code.", example = "INVALID_CREDENTIALS", requiredMode = Schema.RequiredMode.REQUIRED)
    @JsonProperty("errorCode")
    private ErrorCode errorCode;

    @Schema(description = "Human-readable message.", example = "E-mail or password is invalid.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String message;

    @Schema(description = "Correlation id that tracked the request.", example = "92e2653b-cd23-40b9-a71f-1c3fbd24f973", requiredMode = Schema.RequiredMode.REQUIRED)
    private String correlationId;

    @Schema(description = "Request path.", example = "/api/v1/auth/login", requiredMode = Schema.RequiredMode.REQUIRED)
    private String path;

    @Schema(description = "Optional details that help support decode the error.", example = "MethodArgumentNotValidException: request contains invalid fields", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String details;

    public ApiErrorDto() {
    }

    public ApiErrorDto(Instant timestamp, int status, ErrorCode errorCode, String message, String correlationId, String path, String details) {
        this.timestamp = timestamp;
        this.status = status;
        this.errorCode = errorCode;
        this.message = message;
        this.correlationId = correlationId;
        this.path = path;
        this.details = details;
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

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}
