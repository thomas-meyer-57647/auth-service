package de.innologic.auth.web.error;

import de.innologic.auth.web.filter.CorrelationIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.UUID;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AppException.class)
    public ResponseEntity<ApiErrorDto> handleAppException(AppException ex, HttpServletRequest request, HttpServletResponse response) {
        return build(ex.getStatus(), ex.getErrorCode(), ex.getMessage(), request, response, ex);
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<ApiErrorDto> handleMissingHeader(MissingRequestHeaderException ex, HttpServletRequest request, HttpServletResponse response) {
        String message = ex.getHeaderName() + " header is required";
        return build(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, message, request, response, ex);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorDto> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request, HttpServletResponse response) {
        return build(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Request validation failed", request, response, ex);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiErrorDto> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request, HttpServletResponse response) {
        return build(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Request validation failed", request, response, ex);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiErrorDto> handleAuthentication(AuthenticationException ex, HttpServletRequest request, HttpServletResponse response) {
        return build(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Authentication failed", request, response, ex);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorDto> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request, HttpServletResponse response) {
        return build(HttpStatus.FORBIDDEN, ErrorCode.ACCESS_DENIED, "Access denied", request, response, ex);
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiErrorDto> handleResponseStatus(ResponseStatusException ex, HttpServletRequest request, HttpServletResponse response) {
        HttpStatus status = HttpStatus.resolve(ex.getStatusCode().value());
        HttpStatus resolved = status == null ? HttpStatus.INTERNAL_SERVER_ERROR : status;
        ErrorCode code = switch (resolved) {
            case BAD_REQUEST -> ErrorCode.VALIDATION_ERROR;
            case UNAUTHORIZED -> ErrorCode.INVALID_CREDENTIALS;
            case CONFLICT -> ErrorCode.IDEMPOTENCY_CONFLICT;
            case TOO_MANY_REQUESTS -> ErrorCode.RATE_LIMITED;
            default -> ErrorCode.INTERNAL_ERROR;
        };
        String message = ex.getReason() == null ? "Unexpected error" : ex.getReason();
        return build(resolved, code, message, request, response, ex);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorDto> handleGeneric(Exception ex, HttpServletRequest request, HttpServletResponse response) {
        return build(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR, "Unexpected internal error", request, response, ex);
    }

    private ResponseEntity<ApiErrorDto> build(HttpStatus status, ErrorCode code, String message, HttpServletRequest request, HttpServletResponse response, Throwable throwable) {
        String correlationId = resolveCorrelationId(request);
        response.setHeader(CorrelationIdFilter.HEADER_NAME, correlationId);
        ApiErrorDto body = new ApiErrorDto(
                Instant.now(),
                status.value(),
                code,
                message,
                correlationId,
                request.getRequestURI(),
                detailsFrom(throwable)
        );
        logStatus(status, request.getRequestURI(), correlationId, code, throwable);
        return ResponseEntity.status(status).body(body);
    }

    private void logStatus(HttpStatus status, String path, String correlationId, ErrorCode code, Throwable throwable) {
        if (status.is5xxServerError()) {
            log.error("Server error {} for path={} correlationId={} code={}", status.value(), path, correlationId, code, throwable);
        } else {
            log.info("Responding {} for path={} correlationId={} code={}", status.value(), path, correlationId, code);
        }
    }

    private static String resolveCorrelationId(HttpServletRequest request) {
        String header = request.getHeader(CorrelationIdFilter.HEADER_NAME);
        if (StringUtils.hasText(header)) {
            return header;
        }
        Object attribute = request.getAttribute(CorrelationIdFilter.HEADER_NAME);
        if (attribute instanceof String attributeValue && StringUtils.hasText(attributeValue)) {
            return attributeValue;
        }
        String mdcValue = MDC.get(CorrelationIdFilter.MDC_KEY);
        if (StringUtils.hasText(mdcValue)) {
            return mdcValue;
        }
        String generated = UUID.randomUUID().toString();
        request.setAttribute(CorrelationIdFilter.HEADER_NAME, generated);
        return generated;
    }

    private static String detailsFrom(Throwable throwable) {
        if (throwable == null) {
            return null;
        }
        String message = throwable.getMessage();
        return message == null ? throwable.getClass().getSimpleName() : throwable.getClass().getSimpleName() + ": " + message;
    }
}
