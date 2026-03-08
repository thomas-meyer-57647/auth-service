package de.innologic.auth.logging;

import org.slf4j.Logger;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;

public final class StructuredLogBuilder {

    private final Logger logger;
    private final Map<String, Object> fields = new LinkedHashMap<>();

    private StructuredLogBuilder(Logger logger) {
        this.logger = logger;
    }

    public static StructuredLogBuilder forLogger(Logger logger) {
        return new StructuredLogBuilder(logger);
    }

    public StructuredLogBuilder field(String key, Object value) {
        if (key != null && value != null) {
            fields.put(key, value);
        }
        return this;
    }

    public StructuredLogBuilder event(String eventName) {
        return field("eventName", eventName);
    }

    public StructuredLogBuilder targetService(String targetService) {
        return field("targetService", targetService);
    }

    public StructuredLogBuilder requestPath(String requestPath) {
        return field("requestPath", requestPath);
    }

    public StructuredLogBuilder httpMethod(String method) {
        return field("httpMethod", method);
    }

    public StructuredLogBuilder httpStatus(int status) {
        return field("httpStatus", status);
    }

    public StructuredLogBuilder duration(Duration duration) {
        if (duration != null) {
            return field("durationMs", duration.toMillis());
        }
        return this;
    }

    public StructuredLogBuilder durationMs(long millis) {
        return field("durationMs", millis);
    }

    public StructuredLogBuilder correlationId(String correlationId) {
        return field("correlationId", correlationId);
    }

    public StructuredLogBuilder outcome(String outcome) {
        return field("outcome", outcome);
    }

    public StructuredLogBuilder errorCode(String code) {
        return field("errorCode", code);
    }

    public StructuredLogBuilder action(String action) {
        return field("action", action);
    }

    public StructuredLogBuilder diagnosePurpose(String purpose) {
        return field("diagnosePurpose", purpose);
    }

    public void info(String message) {
        logger.info("{} {}", message, format());
    }

    public void warn(String message) {
        logger.warn("{} {}", message, format());
    }

    public void error(String message, Throwable throwable) {
        logger.error("{} {}", message, format(), throwable);
    }

    private String format() {
        if (fields.isEmpty()) {
            return "{}";
        }
        StringJoiner joiner = new StringJoiner(" ", "[", "]");
        fields.forEach((key, value) -> joiner.add(key + "=" + value));
        return joiner.toString();
    }
}
