package de.innologic.auth.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.domain.entity.IdempotencyRecord;
import de.innologic.auth.domain.entity.RegistrationProcess;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.service.RegistrationService;
import de.innologic.auth.domain.enums.Provider;
import de.innologic.auth.service.SocialAuthService;
import de.innologic.auth.web.dto.RegistrationMfaConfirmRequestDto;
import de.innologic.auth.web.dto.RegistrationMfaConfirmResponseDto;
import de.innologic.auth.web.dto.RegistrationMfaEnrollRequestDto;
import de.innologic.auth.web.dto.RegistrationMfaEnrollResponseDto;
import de.innologic.auth.web.dto.RegistrationStartRequestDto;
import de.innologic.auth.web.dto.RegistrationStartResponseDto;
import de.innologic.auth.web.dto.RegistrationVerifyRequestDto;
import de.innologic.auth.web.dto.RegistrationVerifyResponseDto;
import de.innologic.auth.web.dto.SocialRegistrationRequestDto;
import de.innologic.auth.web.error.ApiErrorDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.logging.StructuredLogBuilder;
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
    private final SocialAuthService socialAuthService;

    public RegistrationController(RegistrationService registrationService,
                                  IdempotencyRepository idempotencyRepository,
                                  ObjectMapper objectMapper,
                                  SocialAuthService socialAuthService) {
        this.registrationService = registrationService;
        this.idempotencyRepository = idempotencyRepository;
        this.objectMapper = objectMapper;
        this.socialAuthService = socialAuthService;
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
        Instant start = Instant.now();
        log.info("Handling registration start for email={} correlationId={}", request.getUserEmail(), correlationId());
        String requestHash = hash("registration:start|" + requestDigest(request));
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                log.info("Replaying stored registration start response for key={} correlationId={}", idempotencyKey, correlationId());
                ResponseEntity<RegistrationStartResponseDto> responseEntity = ResponseEntity.status(record.getResponseStatus())
                        .body(fromJson(record.getResponseBody(), RegistrationStartResponseDto.class));
                logRegistrationStart(start, HttpStatus.valueOf(record.getResponseStatus()), idempotencyKey, "REPLAY", true, request.getTenantId());
                return responseEntity;
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
        ResponseEntity<RegistrationStartResponseDto> responseEntity = ResponseEntity.status(HttpStatus.CREATED).body(response);
        logRegistrationStart(start, HttpStatus.CREATED, idempotencyKey, "SUCCESS", false, request.getTenantId());
        return responseEntity;
    }

    @PostMapping("/social/google")
    @Operation(summary = "Social registration via Google", description = "Starts a registration flow that is backed by a verified Google identity.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "Pending social registration saved and verification mail sent.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationStartResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Social authentication failed or provider unavailable.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Social identity already linked, e-mail already used, or Idempotency-Key reused with a different payload.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<RegistrationStartResponseDto> socialRegistrationGoogle(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "social-google-key")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody SocialRegistrationRequestDto request
    ) {
        Instant start = Instant.now();
        String requestHash = hash("registration:social:google|" + socialRequestDigest(Provider.GOOGLE, request));
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
                RegistrationStartResponseDto cached = fromJson(record.getResponseBody(), RegistrationStartResponseDto.class);
                logSocialRegistration(start, replayStatus, Provider.GOOGLE, idempotencyKey, "REPLAY", true, request.getTenantId());
                return ResponseEntity.status(replayStatus)
                        .body(cached);
            }
        }

        RegistrationStartResponseDto response = socialAuthService.registerWithProvider(Provider.GOOGLE, request);
        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.CREATED.value(), toJson(response));
        ResponseEntity<RegistrationStartResponseDto> responseEntity = ResponseEntity.status(HttpStatus.CREATED).body(response);
        logSocialRegistration(start, HttpStatus.CREATED, Provider.GOOGLE, idempotencyKey, "SUCCESS", false, request.getTenantId());
        return responseEntity;
    }

    @PostMapping("/social/facebook")
    @Operation(summary = "Social registration via Facebook", description = "Starts a registration flow that is backed by a verified Facebook identity.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "Pending social registration saved and verification mail sent.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = RegistrationStartResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Social authentication failed or provider unavailable.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Social identity already linked, e-mail already used, or Idempotency-Key reused with a different payload.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<RegistrationStartResponseDto> socialRegistrationFacebook(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "social-facebook-key")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody SocialRegistrationRequestDto request
    ) {
        Instant start = Instant.now();
        String requestHash = hash("registration:social:facebook|" + socialRequestDigest(Provider.FACEBOOK, request));
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
                RegistrationStartResponseDto cached = fromJson(record.getResponseBody(), RegistrationStartResponseDto.class);
                logSocialRegistration(start, replayStatus, Provider.FACEBOOK, idempotencyKey, "REPLAY", true, request.getTenantId());
                return ResponseEntity.status(replayStatus)
                        .body(cached);
            }
        }

        RegistrationStartResponseDto response = socialAuthService.registerWithProvider(Provider.FACEBOOK, request);
        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.CREATED.value(), toJson(response));
        ResponseEntity<RegistrationStartResponseDto> responseEntity = ResponseEntity.status(HttpStatus.CREATED).body(response);
        logSocialRegistration(start, HttpStatus.CREATED, Provider.FACEBOOK, idempotencyKey, "SUCCESS", false, request.getTenantId());
        return responseEntity;
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
        Instant start = Instant.now();
        String requestHash = hash("registration:verify|" + request.getRegistrationId() + "|" + request.getVerificationToken());
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
                RegistrationVerifyResponseDto cached = fromJson(record.getResponseBody(), RegistrationVerifyResponseDto.class);
                logRegistrationVerify(start, replayStatus, idempotencyKey, request.getRegistrationId(), "REPLAY", true);
                return ResponseEntity.status(replayStatus)
                        .body(cached);
            }
        }

        RegistrationProcess process = registrationService.verifyEmail(request);
        RegistrationVerifyResponseDto response = new RegistrationVerifyResponseDto(
                process.getRegistrationId(),
                process.getStatus(),
                "E-mail verified, activation can continue."
        );

        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.OK.value(), toJson(response));
        ResponseEntity<RegistrationVerifyResponseDto> responseEntity = ResponseEntity.ok(response);
        logRegistrationVerify(start, HttpStatus.OK, idempotencyKey, request.getRegistrationId(), "SUCCESS", false);
        return responseEntity;
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
        Instant start = Instant.now();
        String requestHash = hash("registration:mfa:enroll|" + request.getRegistrationId());
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
                RegistrationMfaEnrollResponseDto cached = fromJson(record.getResponseBody(), RegistrationMfaEnrollResponseDto.class);
                logMfaEnroll(start, replayStatus, idempotencyKey, request.getRegistrationId(), "REPLAY", true);
                return ResponseEntity.status(replayStatus)
                        .body(cached);
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
        ResponseEntity<RegistrationMfaEnrollResponseDto> responseEntity = ResponseEntity.ok(response);
        logMfaEnroll(start, HttpStatus.OK, idempotencyKey, request.getRegistrationId(), "SUCCESS", false);
        return responseEntity;
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
        Instant start = Instant.now();
        String requestHash = hash("registration:mfa:confirm|" + request.getRegistrationId() + "|" + request.getTotpCode());
        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
                RegistrationMfaConfirmResponseDto cached = fromJson(record.getResponseBody(), RegistrationMfaConfirmResponseDto.class);
                logMfaConfirm(start, replayStatus, idempotencyKey, request.getRegistrationId(), "REPLAY", true);
                return ResponseEntity.status(replayStatus)
                        .body(cached);
            }
        }

        RegistrationProcess process = registrationService.confirmTotp(request.getRegistrationId(), request.getTotpCode());
        RegistrationMfaConfirmResponseDto response = new RegistrationMfaConfirmResponseDto(
                process.getRegistrationId(),
                process.getStatus(),
                "MFA confirmed; activation completed."
        );

        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.OK.value(), toJson(response));
        ResponseEntity<RegistrationMfaConfirmResponseDto> responseEntity = ResponseEntity.ok(response);
        logMfaConfirm(start, HttpStatus.OK, idempotencyKey, request.getRegistrationId(), "SUCCESS", false);
        return responseEntity;
    }

    private void ensureSamePayload(IdempotencyRecord record, String requestHash) {
        if (!Objects.equals(record.getRequestHash(), requestHash)) {
            throw new AppException(HttpStatus.CONFLICT, ErrorCode.IDEMPOTENCY_CONFLICT, "Idempotency-Key already used with a different payload");
        }
    }

    private void logSocialRegistration(Instant start,
                                      HttpStatus status,
                                      Provider provider,
                                      String idempotencyKey,
                                      String outcome,
                                      boolean replay,
                                      String tenantId) {
        Duration duration = Duration.between(start, Instant.now());
        StructuredLogBuilder.forLogger(log)
                .event("registration.social." + provider.name().toLowerCase())
                .targetService("auth-service")
                .requestPath("/registration/social/" + provider.name().toLowerCase())
                .httpMethod("POST")
                .httpStatus(status != null ? status.value() : HttpStatus.OK.value())
                .duration(duration)
                .outcome(outcome)
                .correlationId(correlationId())
                .field("idempotencyKey", idempotencyKey)
                .field("provider", provider.name())
                .field("tenantId", tenantId)
                .field("replay", replay)
                .info(replay ? "Social registration replayed" : "Social registration executed");
    }

    private void logRegistrationVerify(Instant start,
                                       HttpStatus status,
                                       String idempotencyKey,
                                       String registrationId,
                                       String outcome,
                                       boolean replay) {
        Duration duration = Duration.between(start, Instant.now());
        StructuredLogBuilder.forLogger(log)
                .event("registration.verify")
                .targetService("auth-service")
                .requestPath("/registration/verify-email")
                .httpMethod("POST")
                .httpStatus(status != null ? status.value() : HttpStatus.OK.value())
                .duration(duration)
                .outcome(outcome)
                .correlationId(correlationId())
                .field("idempotencyKey", idempotencyKey)
                .field("registrationId", registrationId)
                .field("replay", replay)
                .info(replay ? "Registration verify replayed" : "Registration verify executed");
    }

    private void logMfaEnroll(Instant start,
                              HttpStatus status,
                              String idempotencyKey,
                              String registrationId,
                              String outcome,
                              boolean replay) {
        Duration duration = Duration.between(start, Instant.now());
        StructuredLogBuilder.forLogger(log)
                .event("registration.mfa.enroll")
                .targetService("auth-service")
                .requestPath("/registration/mfa/totp/enroll")
                .httpMethod("POST")
                .httpStatus(status != null ? status.value() : HttpStatus.OK.value())
                .duration(duration)
                .outcome(outcome)
                .correlationId(correlationId())
                .field("idempotencyKey", idempotencyKey)
                .field("registrationId", registrationId)
                .field("replay", replay)
                .info(replay ? "MFA enrollment replayed" : "MFA enrollment executed");
    }

    private void logMfaConfirm(Instant start,
                               HttpStatus status,
                               String idempotencyKey,
                               String registrationId,
                               String outcome,
                               boolean replay) {
        Duration duration = Duration.between(start, Instant.now());
        StructuredLogBuilder.forLogger(log)
                .event("registration.mfa.confirm")
                .targetService("auth-service")
                .requestPath("/registration/mfa/totp/confirm")
                .httpMethod("POST")
                .httpStatus(status != null ? status.value() : HttpStatus.OK.value())
                .duration(duration)
                .outcome(outcome)
                .correlationId(correlationId())
                .field("idempotencyKey", idempotencyKey)
                .field("registrationId", registrationId)
                .field("replay", replay)
                .info(replay ? "MFA confirm replayed" : "MFA confirm executed");
    }

    private String requestDigest(RegistrationStartRequestDto request) {
        return request.getTenantId() + "|" + request.getUserEmail() + "|" +
                normalized(request.getCompanyPayload()) + "|" +
                normalized(request.getLocationPayload()) + "|" +
                normalized(request.getUserPayload());
    }

    private String socialRequestDigest(Provider provider, SocialRegistrationRequestDto request) {
        return provider.name() + "|" + request.getTenantId() + "|" +
                normalized(request.getCompanyPayload()) + "|" +
                normalized(request.getLocationPayload()) + "|" +
                normalized(request.getUserPayload()) + "|" +
                request.getSocialToken();
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

    private void logRegistrationStart(Instant start,
                                      HttpStatus status,
                                      String idempotencyKey,
                                      String outcome,
                                      boolean replay,
                                      String tenantId) {
        Duration duration = Duration.between(start, Instant.now());
        StructuredLogBuilder.forLogger(log)
                .event("registration.start")
                .targetService("auth-service")
                .requestPath("/registration/start")
                .httpMethod("POST")
                .httpStatus(status.value())
                .duration(duration)
                .outcome(outcome)
                .correlationId(correlationId())
                .field("idempotencyKey", idempotencyKey)
                .field("tenantId", tenantId)
                .field("replay", replay)
                .info(replay ? "Registration start replayed" : "Registration start executed");
    }
}
