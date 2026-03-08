package de.innologic.auth.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.domain.entity.IdempotencyRecord;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.service.CredentialRecoveryService;
import de.innologic.auth.web.dto.AcceptedResponseDto;
import de.innologic.auth.web.dto.LogoutResponseDto;
import de.innologic.auth.web.dto.MfaRecoveryConfirmRequestDto;
import de.innologic.auth.web.dto.MfaRecoveryStartRequestDto;
import de.innologic.auth.logging.StructuredLogBuilder;
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
@RequestMapping(path = "/mfa/recovery", produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "MFA Recovery", description = "Endpoints to recover MFA configuration when a second factor is lost.")
public class MfaRecoveryController {

    private static final Duration IDEMPOTENCY_TTL = Duration.ofHours(24);
    private static final Logger log = LoggerFactory.getLogger(MfaRecoveryController.class);

    private final CredentialRecoveryService credentialRecoveryService;
    private final IdempotencyRepository idempotencyRepository;
    private final ObjectMapper objectMapper;

    public MfaRecoveryController(
            CredentialRecoveryService credentialRecoveryService,
            IdempotencyRepository idempotencyRepository,
            ObjectMapper objectMapper
    ) {
        this.credentialRecoveryService = credentialRecoveryService;
        this.idempotencyRepository = idempotencyRepository;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/start")
    @Operation(
            summary = "Start MFA recovery",
            description = "Creates a short-lived recovery token (hashed in DB) and sends it to the configured channel. " +
                    "Requires an Idempotency-Key header."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "202",
                    description = "Neutral acknowledgement.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AcceptedResponseDto.class),
                            examples = @ExampleObject(value = "{\"message\":\"If recovery is available, instructions were sent.\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class)
                    )
            )
    })
    public ResponseEntity<AcceptedResponseDto> start(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "mfa-recovery-start-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody MfaRecoveryStartRequestDto request
    ) {
        String requestHash = hash("mfa-recovery-start|" + request.getEmail() + "|" + request.getChannel());
        Instant start = Instant.now();
        return processIdempotentResponse(
                start,
                "mfa.recovery.start",
                "/mfa/recovery/start",
                idempotencyKey,
                requestHash,
                AcceptedResponseDto.class,
                () -> {
                    credentialRecoveryService.startMfaRecovery(request.getEmail(), request.getChannel());
                    return ResponseEntity.accepted().body(new AcceptedResponseDto("If recovery is available, instructions were sent."));
                }
        );
    }

    @PostMapping("/confirm")
    @Operation(
            summary = "Confirm MFA recovery",
            description = "Consumes the recovery token, disables the previous MFA config and forces re-enrollment plus session revocation."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Recovery confirmed.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LogoutResponseDto.class),
                            examples = @ExampleObject(value = "{\"message\":\"MFA recovery confirmed\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or expired recovery token.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class)
                    )
            )
    })
    public ResponseEntity<LogoutResponseDto> confirm(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "mfa-recovery-confirm-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody MfaRecoveryConfirmRequestDto request
    ) {
        String requestHash = hash("mfa-recovery-confirm|" + request.getToken());
        Instant start = Instant.now();
        return processIdempotentResponse(
                start,
                "mfa.recovery.confirm",
                "/mfa/recovery/confirm",
                idempotencyKey,
                requestHash,
                LogoutResponseDto.class,
                () -> {
                    credentialRecoveryService.confirmMfaRecovery(request.getToken());
                    return ResponseEntity.ok(new LogoutResponseDto("MFA recovery confirmed"));
                }
        );
    }

    private <T> ResponseEntity<T> processIdempotentResponse(
            Instant start,
            String eventName,
            String requestPath,
            String idempotencyKey,
            String requestHash,
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
                logMfaRecoveryEvent(start, eventName, requestPath, replayStatus, idempotencyKey, "REPLAY", true, null)
                        .info("MFA recovery action replayed");
                return ResponseEntity.status(replayStatus).body(body);
            }

            ResponseEntity<T> response = action.get();
            upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash,
                    response.getStatusCodeValue(), toJson(response.getBody()));
            HttpStatus successStatus = toHttpStatus(response.getStatusCode());
            logMfaRecoveryEvent(start, eventName, requestPath, successStatus, idempotencyKey, "SUCCESS", false, null)
                    .info("MFA recovery action completed");
            return response;
        } catch (AppException ex) {
            logMfaRecoveryEvent(start, eventName, requestPath, ex.getStatus(), idempotencyKey, "FAILURE", false, ex.getErrorCode())
                    .warn("MFA recovery action failed");
            throw ex;
        } catch (RuntimeException ex) {
            logMfaRecoveryEvent(start, eventName, requestPath, HttpStatus.INTERNAL_SERVER_ERROR, idempotencyKey, "FAILURE", false, null)
                    .error("MFA recovery action failed unexpectedly", ex);
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

    private StructuredLogBuilder logMfaRecoveryEvent(Instant start,
                                                     String eventName,
                                                     String requestPath,
                                                     HttpStatus status,
                                                     String idempotencyKey,
                                                     String outcome,
                                                     boolean replay,
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
                .field("replay", replay);
        if (errorCode != null) {
            builder.errorCode(errorCode.name());
        }
        return builder;
    }
}
