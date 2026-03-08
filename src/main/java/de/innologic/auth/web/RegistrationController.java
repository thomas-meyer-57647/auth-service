package de.innologic.auth.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.domain.entity.IdempotencyRecord;
import de.innologic.auth.domain.entity.RegistrationProcess;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.service.RegistrationService;
import de.innologic.auth.web.dto.RegistrationMfaConfirmRequestDto;
import de.innologic.auth.web.dto.RegistrationMfaConfirmResponseDto;
import de.innologic.auth.web.dto.RegistrationMfaEnrollRequestDto;
import de.innologic.auth.web.dto.RegistrationMfaEnrollResponseDto;
import de.innologic.auth.web.dto.RegistrationStartRequestDto;
import de.innologic.auth.web.dto.RegistrationStartResponseDto;
import de.innologic.auth.web.dto.RegistrationVerifyRequestDto;
import de.innologic.auth.web.dto.RegistrationVerifyResponseDto;
import de.innologic.auth.web.error.ApiErrorDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
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

@RestController
@RequestMapping(path = "/registration", produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "Auth", description = "Registration endpoints for the auth service.")
public class RegistrationController {

    private static final Logger log = LoggerFactory.getLogger(RegistrationController.class);
    private static final Duration IDEMPOTENCY_TTL = Duration.ofHours(24);

    private final RegistrationService registrationService;
    private final IdempotencyRepository idempotencyRepository;
    private final ObjectMapper objectMapper;

    public RegistrationController(RegistrationService registrationService,
                                  IdempotencyRepository idempotencyRepository,
                                  ObjectMapper objectMapper) {
        this.registrationService = registrationService;
        this.idempotencyRepository = idempotencyRepository;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/start")
    @Operation(summary = "Start registration", description = "Creates the pending registration context, stores the registration process and triggers the verification mail.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "Pending registration saved and verification mail sent.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationStartResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation failed or request hash mismatch.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "E-mail already exists or Idempotency-Key reused with different payload.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<RegistrationStartResponseDto> startRegistration(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "a1b2c3d4-e5f6-4a8e-b3c9-370e2fd6be73")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody RegistrationStartRequestDto request
    ) {
        log.info("Handling registration start for email={} correlationId={}", request.getUserEmail(), correlationId());
        String requestHash = hash("registration:start|" + requestDigest(request));
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                log.info("Replaying stored registration start response for key={} correlationId={}", idempotencyKey, correlationId());
                return ResponseEntity.status(record.getResponseStatus())
                        .body(fromJson(record.getResponseBody(), RegistrationStartResponseDto.class));
            }
        }

        RegistrationProcess process = registrationService.startRegistration(request).getProcess();
        RegistrationStartResponseDto response = new RegistrationStartResponseDto(
                process.getRegistrationId(),
                process.getStatus(),
                process.getExpiresAt(),
                "Registration initiated; verification e-mail has been queued."
        );

        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.CREATED.value(), toJson(response));
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Verify the registration e-mail", description = "Validates the token for the pending registration and marks the email as verified.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "E-mail verified.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationVerifyResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Request validation failed or token invalid.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Verification token expired.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Registration not found.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "410",
                    description = "Registration expired.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Idempotency-Key reused with a different payload.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<RegistrationVerifyResponseDto> verifyEmail(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "verified-key-1234")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody RegistrationVerifyRequestDto request
    ) {
        log.info("Handling registration verify for registrationId={} correlationId={}", request.getRegistrationId(), correlationId());
        String requestHash = hash("registration:verify|" + request.getRegistrationId() + "|" + request.getVerificationToken());
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                log.info("Replaying stored registration verify response for key={} correlationId={}", idempotencyKey, correlationId());
                return ResponseEntity.status(record.getResponseStatus())
                        .body(fromJson(record.getResponseBody(), RegistrationVerifyResponseDto.class));
            }
        }

        RegistrationProcess process = registrationService.verifyEmail(request);
        RegistrationVerifyResponseDto response = new RegistrationVerifyResponseDto(
                process.getRegistrationId(),
                process.getStatus(),
                "E-mail verified, activation can continue."
        );

        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.OK.value(), toJson(response));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/mfa/totp/enroll")
    @Operation(summary = "Start MFA/TOTP enrollment", description = "Prepares TOTP enrollment data for the Authenticator app after the e-mail verification has completed.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Enrollment data created.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationMfaEnrollResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation failed, MFA disabled or e-mail not verified.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Idempotency-Key reused with a different payload.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<RegistrationMfaEnrollResponseDto> enrollMfa(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "mfa-enroll-key-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody RegistrationMfaEnrollRequestDto request
    ) {
        log.info("Handling MFA enrollment for registrationId={} correlationId={}", request.getRegistrationId(), correlationId());
        String requestHash = hash("registration:mfa:enroll|" + request.getRegistrationId());
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                log.info("Replaying stored MFA enrollment response for key={} correlationId={}", idempotencyKey, correlationId());
                return ResponseEntity.status(record.getResponseStatus())
                        .body(fromJson(record.getResponseBody(), RegistrationMfaEnrollResponseDto.class));
            }
        }

        RegistrationService.MfaEnrollmentResult enrollment = registrationService.enrollTotp(request.getRegistrationId());
        RegistrationMfaEnrollResponseDto response = new RegistrationMfaEnrollResponseDto(
                request.getRegistrationId(),
                enrollment.getSecret(),
                enrollment.getOtpauthUri(),
                "MFA_ENROLLMENT_PREPARED"
        );

        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.OK.value(), toJson(response));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/mfa/totp/confirm")
    @Operation(summary = "Confirm TOTP enrollment", description = "Confirms the TOTP code after MFA enrollment and completes activation.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "MFA confirmed and registration activated.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationMfaConfirmResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation failed, token invalid, or MFA disabled.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Idempotency-Key reused with a different payload.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<RegistrationMfaConfirmResponseDto> confirmMfa(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "mfa-confirm-key-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody RegistrationMfaConfirmRequestDto request
    ) {
        log.info("Handling MFA confirm for registrationId={} correlationId={}", request.getRegistrationId(), correlationId());
        String requestHash = hash("registration:mfa:confirm|" + request.getRegistrationId() + "|" + request.getTotpCode());
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                log.info("Replaying stored MFA confirm response for key={} correlationId={}", idempotencyKey, correlationId());
                return ResponseEntity.status(record.getResponseStatus())
                        .body(fromJson(record.getResponseBody(), RegistrationMfaConfirmResponseDto.class));
            }
        }

        RegistrationProcess process = registrationService.confirmTotp(request.getRegistrationId(), request.getTotpCode());
        RegistrationMfaConfirmResponseDto response = new RegistrationMfaConfirmResponseDto(
                process.getRegistrationId(),
                process.getStatus(),
                "MFA confirmed; activation completed."
        );

        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.OK.value(), toJson(response));
        return ResponseEntity.ok(response);
    }

    private void ensureSamePayload(IdempotencyRecord record, String requestHash) {
        if (!Objects.equals(record.getRequestHash(), requestHash)) {
            throw new AppException(HttpStatus.CONFLICT, ErrorCode.IDEMPOTENCY_CONFLICT, "Idempotency-Key already used with a different payload");
        }
    }

    private String requestDigest(RegistrationStartRequestDto request) {
        return request.getTenantId() + "|" + request.getUserEmail() + "|" +
                normalized(request.getCompanyPayload()) + "|" +
                normalized(request.getLocationPayload()) + "|" +
                normalized(request.getUserPayload());
    }

    private String normalized(JsonNode node) {
        if (node == null) {
            return "";
        }
        try {
            return objectMapper.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Unable to serialize registration payload");
        }
    }

    private void upsertIdempotencyRecord(IdempotencyRecord record, String key, String hash, int status, String body) {
        Instant now = Instant.now();
        if (record.getId() == null) {
            record.setCreatedAt(now);
        }
        record.setIdempotencyKey(key);
        record.setRequestHash(hash);
        record.setResponseStatus(status);
        record.setResponseBody(body);
        record.setExpiresAt(now.plus(IDEMPOTENCY_TTL));
        idempotencyRepository.save(record);
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Unable to serialize idempotent response");
        }
    }

    private <T> T fromJson(String json, Class<T> clazz) {
        try {
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Unable to deserialize idempotent response");
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
}
