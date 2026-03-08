package de.innologic.auth.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.domain.entity.IdempotencyRecord;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.logging.StructuredLogBuilder;
import de.innologic.auth.security.jwt.JwtTokenService;
import de.innologic.auth.web.dto.AccessTokenResponseDto;
import de.innologic.auth.web.dto.ServiceTokenRequestDto;
import de.innologic.auth.web.error.ApiErrorDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;

@RestController
@RequestMapping(path = "/internal/tokens", produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "Internal Tokens", description = "Issuance of short-lived tokens for internal service-to-service communication.")
public class InternalTokensController {

    private static final Duration IDEMPOTENCY_TTL = Duration.ofHours(24);
    private static final Logger log = LoggerFactory.getLogger(InternalTokensController.class);
    private static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";

    private final JwtTokenService jwtTokenService;
    private final IdempotencyRepository idempotencyRepository;
    private final ObjectMapper objectMapper;
    private final String internalApiKey;

    public InternalTokensController(
            JwtTokenService jwtTokenService,
            IdempotencyRepository idempotencyRepository,
            ObjectMapper objectMapper,
            @Value("${auth.internal.api-key:}") String internalApiKey
    ) {
        this.jwtTokenService = jwtTokenService;
        this.idempotencyRepository = idempotencyRepository;
        this.objectMapper = objectMapper;
        this.internalApiKey = internalApiKey;
    }

    @PostMapping("/service")
    @Operation(
            summary = "Issue internal service token",
            description = "Generates a short-lived token for internal calls. Idempotency-Key and internal API key headers are required."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Service token issued for internal calls.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AccessTokenResponseDto.class),
                            examples = @ExampleObject(value = "{\"accessToken\":\"<jwt>\",\"tokenType\":\"Bearer\",\"expiresIn\":300}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error or TTL out of range.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid internal API key.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class)
                    )
            )
    })
    public ResponseEntity<AccessTokenResponseDto> issueServiceToken(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "service-token-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Parameter(description = "Internal API key for trusted services.", required = true, example = "internal-test-key")
            @NotBlank @RequestHeader(value = INTERNAL_API_KEY_HEADER) String headerValue,
            @Valid @RequestBody ServiceTokenRequestDto request
    ) {
        verifyInternalApiKey(headerValue);

        Duration requestedTtl = request.getTtlSeconds() != null ? Duration.ofSeconds(request.getTtlSeconds()) : null;
        Duration tokenTtl = jwtTokenService.resolveServiceTokenTtl(requestedTtl);

        String audSegment = String.join(",", request.getAud());
        String scopeSegment = String.join(",", request.getScopes());
        String requestHash = hash("service-token|" + request.getServiceName() + "|"
                + request.getTenantId() + "|" + audSegment + "|" + scopeSegment + "|" + tokenTtl.getSeconds());

        Instant start = Instant.now();
        return processIdempotentResponse(
                start,
                "internal.token.issue",
                "/internal/tokens/service",
                idempotencyKey,
                requestHash,
                request.getServiceName(),
                request.getTenantId(),
                AccessTokenResponseDto.class,
                () -> {
                    String token = jwtTokenService.issueServiceToken(
                            request.getServiceName(),
                            request.getTenantId(),
                            request.getAud(),
                            request.getScopes(),
                            tokenTtl
                    );
                    AccessTokenResponseDto response = new AccessTokenResponseDto(token, "Bearer", tokenTtl.getSeconds());
                    return ResponseEntity.ok(response);
                }
        );
    }

    private <T> ResponseEntity<T> processIdempotentResponse(
            Instant start,
            String eventName,
            String requestPath,
            String idempotencyKey,
            String requestHash,
            String serviceName,
            String tenantId,
            Class<T> responseClass,
            Supplier<ResponseEntity<T>> action
    ) {
        try {
            Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
            if (existing.isPresent()) {
                IdempotencyRecord record = existing.get();
                ensureSamePayload(record, requestHash);
                T body = null;
                if (record.getResponseBody() != null && responseClass != null) {
                    body = fromJson(record.getResponseBody(), responseClass);
                }
                HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
            logServiceTokenEvent(start, eventName, requestPath, replayStatus, idempotencyKey, "REPLAY", true, serviceName, tenantId, null)
                        .info("Internal token action replayed");
                return ResponseEntity.status(replayStatus).body(body);
            }

            ResponseEntity<T> response = action.get();
            upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash,
                    response.getStatusCodeValue(), toJson(response.getBody()));
            HttpStatus successStatus = toHttpStatus(response.getStatusCode());
            logServiceTokenEvent(start, eventName, requestPath, successStatus, idempotencyKey, "SUCCESS", false, serviceName, tenantId, null)
                    .info("Internal token action completed");
            return response;
        } catch (AppException ex) {
            logServiceTokenEvent(start, eventName, requestPath, ex.getStatus(), idempotencyKey, "FAILURE", false, serviceName, tenantId, ex.getErrorCode())
                    .warn("Internal token action failed");
            throw ex;
        } catch (RuntimeException ex) {
            logServiceTokenEvent(start, eventName, requestPath, HttpStatus.INTERNAL_SERVER_ERROR, idempotencyKey, "FAILURE", false, serviceName, tenantId, null)
                    .error("Internal token action failed unexpectedly", ex);
            throw ex;
        }
    }

    private void ensureSamePayload(IdempotencyRecord record, String requestHash) {
        if (!Objects.equals(record.getRequestHash(), requestHash)) {
            throw new AppException(CONFLICT, ErrorCode.IDEMPOTENCY_CONFLICT, "Idempotency-Key already used with a different payload");
        }
    }

    private void upsertIdempotencyRecord(IdempotencyRecord record, String key, String requestHash, int status, String body) {
        Instant now = Instant.now();
        if (record.getId() == null) {
            record.setCreatedAt(now);
        }
        record.setIdempotencyKey(key);
        record.setRequestHash(requestHash);
        record.setResponseStatus(status);
        record.setResponseBody(body);
        record.setExpiresAt(now.plus(IDEMPOTENCY_TTL));
        idempotencyRepository.save(record);
    }

    private String toJson(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new AppException(BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Unable to serialize idempotent response");
        }
    }

    private <T> T fromJson(String json, Class<T> clazz) {
        try {
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new AppException(BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Unable to deserialize idempotent response");
        }
    }

    private String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashed) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String correlationId() {
        String value = MDC.get(CorrelationIdFilter.MDC_KEY);
        return value == null ? "n/a" : value;
    }

    private HttpStatus toHttpStatus(HttpStatusCode statusCode) {
        if (statusCode == null) {
            return HttpStatus.OK;
        }
        HttpStatus resolved = HttpStatus.resolve(statusCode.value());
        return resolved != null ? resolved : HttpStatus.valueOf(statusCode.value());
    }

    private StructuredLogBuilder logServiceTokenEvent(Instant start,
                                                    String eventName,
                                                    String requestPath,
                                                    HttpStatus status,
                                                    String idempotencyKey,
                                                    String outcome,
                                                    boolean replay,
                                                    String serviceName,
                                                    String tenantId,
                                                    ErrorCode errorCode) {
        Duration duration = Duration.between(start, Instant.now());
        StructuredLogBuilder builder = StructuredLogBuilder.forLogger(log)
                .event(eventName)
                .targetService("auth-service")
                .requestPath(requestPath)
                .httpMethod("POST")
                .httpStatus(status != null ? status.value() : HttpStatus.OK.value())
                .duration(duration)
                .outcome(outcome)
                .correlationId(correlationId())
                .field("idempotencyKey", idempotencyKey)
                .field("service", serviceName)
                .field("tenantId", tenantId)
                .field("replay", replay);
        if (errorCode != null) {
            builder.errorCode(errorCode.name());
        }
        return builder;
    }

    private void verifyInternalApiKey(String headerValue) {
        if (internalApiKey == null || internalApiKey.isBlank()) {
            return;
        }
        if (!Objects.equals(internalApiKey, headerValue)) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.INTERNAL_API_KEY_INVALID, "Invalid internal API key");
        }
    }
}
