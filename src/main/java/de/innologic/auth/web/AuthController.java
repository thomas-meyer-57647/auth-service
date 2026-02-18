package de.innologic.auth.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.config.MFAConfig;
import de.innologic.auth.domain.entity.Credential;
import de.innologic.auth.domain.entity.IdempotencyRecord;
import de.innologic.auth.domain.entity.Mfa;
import de.innologic.auth.domain.entity.Session;
import de.innologic.auth.domain.enums.SessionPolicy;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.domain.repository.MfaRepository;
import de.innologic.auth.security.jwt.JwtTokenService;
import de.innologic.auth.service.CredentialRecoveryService;
import de.innologic.auth.service.SessionService;
import de.innologic.auth.web.dto.AcceptedResponseDto;
import de.innologic.auth.web.dto.AccessTokenResponseDto;
import de.innologic.auth.web.dto.LoginRequestDto;
import de.innologic.auth.web.dto.LoginResponseDto;
import de.innologic.auth.web.dto.LogoutResponseDto;
import de.innologic.auth.web.dto.MfaRecoveryConfirmRequestDto;
import de.innologic.auth.web.dto.MfaRecoveryStartRequestDto;
import de.innologic.auth.web.dto.MfaVerifyRequestDto;
import de.innologic.auth.web.dto.PasswordForgotRequestDto;
import de.innologic.auth.web.dto.PasswordResetRequestDto;
import de.innologic.auth.web.error.ApiErrorDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "Auth", description = "Authentication endpoints for login, MFA verify, refresh and logout.")
public class AuthController {

    private static final String REFRESH_COOKIE_NAME = "AUTH_REFRESH";
    private static final Duration LOGIN_TRANSACTION_TTL = Duration.ofMinutes(5);
    private static final Duration IDEMPOTENCY_TTL = Duration.ofHours(24);

    private final CredentialRepository credentialRepository;
    private final MfaRepository mfaRepository;
    private final IdempotencyRepository idempotencyRepository;
    private final JwtTokenService jwtTokenService;
    private final SessionService sessionService;
    private final CredentialRecoveryService credentialRecoveryService;
    private final MFAConfig mfaConfig;
    private final ObjectMapper objectMapper;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final Map<String, PendingLoginTransaction> loginTransactions = new ConcurrentHashMap<>();

    private final String defaultTenantId;
    private final List<String> defaultAudiences;
    private final List<String> defaultScopes;
    private final Duration accessTokenTtl;

    public AuthController(
            CredentialRepository credentialRepository,
            MfaRepository mfaRepository,
            IdempotencyRepository idempotencyRepository,
            JwtTokenService jwtTokenService,
            SessionService sessionService,
            CredentialRecoveryService credentialRecoveryService,
            MFAConfig mfaConfig,
            ObjectMapper objectMapper,
            @Value("${auth.default-tenant-id:default}") String defaultTenantId,
            @Value("${auth.default-audience:auth-api}") String defaultAudience,
            @Value("${auth.default-scopes:openid,profile}") String defaultScopes,
            @Value("${auth.jwt.access-token-ttl:PT15M}") Duration accessTokenTtl
    ) {
        this.credentialRepository = credentialRepository;
        this.mfaRepository = mfaRepository;
        this.idempotencyRepository = idempotencyRepository;
        this.jwtTokenService = jwtTokenService;
        this.sessionService = sessionService;
        this.credentialRecoveryService = credentialRecoveryService;
        this.mfaConfig = mfaConfig;
        this.objectMapper = objectMapper;
        this.defaultTenantId = defaultTenantId;
        this.defaultAudiences = splitCsv(defaultAudience);
        this.defaultScopes = splitCsv(defaultScopes);
        this.accessTokenTtl = accessTokenTtl;
    }

    @PostMapping("/login")
    @Operation(
            summary = "Start login transaction",
            description = "Validates e-mail/password and returns a short-lived loginTransactionId used by /mfa/verify. " +
                    "Requires Idempotency-Key header and stores response in idempotency table."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Login transaction created.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponseDto.class),
                            examples = @ExampleObject(value = "{\"loginTransactionId\":\"ltx_1fbe4b0c4dbb4a8d85f7037f0f5c4ad8\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation or request format error.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":400,\"code\":\"VALIDATION_ERROR\",\"message\":\"Request validation failed\",\"path\":\"/api/v1/auth/login\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":401,\"code\":\"INVALID_CREDENTIALS\",\"message\":\"Invalid e-mail or password\",\"path\":\"/api/v1/auth/login\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Idempotency-Key reused with different payload.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":409,\"code\":\"IDEMPOTENCY_CONFLICT\",\"message\":\"Idempotency-Key already used with a different payload\",\"path\":\"/api/v1/auth/login\"}")
                    )
            )
    })
    public ResponseEntity<LoginResponseDto> login(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "f84f5f4f-c13f-4f73-b2f1-62a95e3604d9")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody LoginRequestDto request
    ) {
        String requestHash = hash("login|" + request.getEmail() + "|" + request.getPassword());

        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                return ResponseEntity.status(record.getResponseStatus())
                        .body(fromJson(record.getResponseBody(), LoginResponseDto.class));
            }
        }

        Credential credential = credentialRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Invalid e-mail or password"));

        if (credential.getPasswordHash() == null || !passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
            throw new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Invalid e-mail or password");
        }

        String loginTransactionId = "ltx_" + UUID.randomUUID().toString().replace("-", "");
        loginTransactions.put(loginTransactionId, new PendingLoginTransaction(credential.getId(), Instant.now()));

        LoginResponseDto response = new LoginResponseDto(loginTransactionId);
        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, 200, toJson(response));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/mfa/verify")
    @Operation(
            summary = "Verify TOTP and issue tokens",
            description = "Verifies MFA code for login transaction, creates a refresh session, sets HttpOnly refresh cookie and returns access token. " +
                    "Requires Idempotency-Key header and stores response in idempotency table."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "MFA successful.",
                    headers = @Header(name = HttpHeaders.SET_COOKIE, description = "HttpOnly refresh cookie."),
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AccessTokenResponseDto.class),
                            examples = @ExampleObject(value = "{\"accessToken\":\"eyJraWQiOiJkZXYtcnNhLWtleS0xIiwiYWxnIjoiUlMyNTYifQ...\",\"tokenType\":\"Bearer\",\"expiresIn\":900}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request, transaction expired or invalid TOTP.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":400,\"code\":\"TOKEN_INVALID\",\"message\":\"Invalid or expired loginTransactionId\",\"path\":\"/api/v1/auth/mfa/verify\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "MFA not configured/enabled or code invalid.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":400,\"code\":\"TOTP_INVALID\",\"message\":\"Invalid TOTP code\",\"path\":\"/api/v1/auth/mfa/verify\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Idempotency-Key reused with different payload.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":409,\"code\":\"IDEMPOTENCY_CONFLICT\",\"message\":\"Idempotency-Key already used with a different payload\",\"path\":\"/api/v1/auth/mfa/verify\"}")
                    )
            )
    })
    public ResponseEntity<AccessTokenResponseDto> verifyMfa(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "774063e2-3e45-4fe5-978f-fb219ce53d6e")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody MfaVerifyRequestDto request,
            HttpServletRequest httpRequest
    ) {
        String requestHash = hash("mfa|" + request.getLoginTransactionId() + "|" + request.getTotpCode() + "|" + request.getSessionPolicy());

        Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            IdempotencyRecord record = existing.get();
            ensureSamePayload(record, requestHash);
            if (record.getResponseBody() != null) {
                MfaVerifyReplayPayload replay = fromJson(record.getResponseBody(), MfaVerifyReplayPayload.class);
                return ResponseEntity.status(record.getResponseStatus())
                        .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(replay.getRefreshToken(), request.getSessionPolicy()).toString())
                        .body(replay.getAccessToken());
            }
        }

        cleanupExpiredTransactions();
        PendingLoginTransaction pending = loginTransactions.remove(request.getLoginTransactionId());
        if (pending == null || pending.createdAt().plus(LOGIN_TRANSACTION_TTL).isBefore(Instant.now())) {
            throw new AppException(BAD_REQUEST, ErrorCode.TOKEN_INVALID, "Invalid or expired loginTransactionId");
        }

        Mfa mfa = mfaRepository.findByCredentialId(pending.credentialId())
                .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.MFA_REQUIRED, "MFA enrollment missing"));

        if (!mfa.isEnabled() || mfa.getSecretEncrypted() == null || mfa.getSecretEncrypted().isBlank()) {
            throw new AppException(UNAUTHORIZED, ErrorCode.MFA_REQUIRED, "MFA is not enabled");
        }

        if (!isValidTotp(request.getTotpCode(), mfa.getSecretEncrypted(), Instant.now())) {
            throw new AppException(BAD_REQUEST, ErrorCode.TOTP_INVALID, "Invalid TOTP code");
        }

        SessionService.SessionWithToken sessionWithToken = sessionService.createSession(
                loadCredential(pending.credentialId()),
                request.getSessionPolicy(),
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader(HttpHeaders.USER_AGENT)
        );
        Session session = sessionWithToken.session();
        String refreshToken = sessionWithToken.refreshToken();

        String accessToken = jwtTokenService.issueAccessToken(
                pending.credentialId(),
                defaultTenantId,
                String.valueOf(session.getId()),
                defaultAudiences,
                defaultScopes,
                List.of("pwd", "totp")
        );

        AccessTokenResponseDto response = new AccessTokenResponseDto(accessToken, "Bearer", accessTokenTtl.toSeconds());
        MfaVerifyReplayPayload replayPayload = new MfaVerifyReplayPayload(response, refreshToken);

        upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, 200, toJson(replayPayload));

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(refreshToken, request.getSessionPolicy()).toString())
                .body(response);
    }

    @PostMapping("/refresh")
    @Operation(
            summary = "Issue new access token",
            description = "Uses refresh cookie to load active session and returns a new access token."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Token refreshed.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AccessTokenResponseDto.class),
                            examples = @ExampleObject(value = "{\"accessToken\":\"eyJraWQiOiJkZXYtcnNhLWtleS0xIiwiYWxnIjoiUlMyNTYifQ...\",\"tokenType\":\"Bearer\",\"expiresIn\":900}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Refresh cookie missing/invalid or session revoked/expired.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":401,\"code\":\"REFRESH_INVALID\",\"message\":\"Refresh token is invalid\",\"path\":\"/api/v1/auth/refresh\"}")
                    )
            )
    })
    public ResponseEntity<AccessTokenResponseDto> refresh(HttpServletRequest request) {
        String refreshToken = readCookie(request, REFRESH_COOKIE_NAME)
                .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.REFRESH_INVALID, "Refresh cookie missing"));

        SessionService.RotationResult rotation = sessionService.rotateRefreshToken(refreshToken);
        Session session = rotation.session();

        String accessToken = jwtTokenService.issueAccessToken(
                session.getCredential().getId(),
                defaultTenantId,
                String.valueOf(session.getId()),
                defaultAudiences,
                defaultScopes,
                List.of("refresh")
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(rotation.newRefreshToken(), session.getSessionPolicy()).toString())
                .body(new AccessTokenResponseDto(accessToken, "Bearer", accessTokenTtl.toSeconds()));
    }

    @PostMapping("/logout")
    @Operation(
            summary = "Logout current session",
            description = "Revokes current refresh session and clears refresh cookie."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Logout completed.",
                    headers = @Header(name = HttpHeaders.SET_COOKIE, description = "Refresh cookie cleared."),
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LogoutResponseDto.class),
                            examples = @ExampleObject(value = "{\"message\":\"Logged out\"}")
                    )
            )
    })
    public ResponseEntity<LogoutResponseDto> logout(HttpServletRequest request) {
        readCookie(request, REFRESH_COOKIE_NAME).ifPresent(sessionService::revokeSessionByRefreshToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString())
                .body(new LogoutResponseDto("Logged out"));
    }

    @PostMapping("/password/forgot")
    @Operation(
            summary = "Start password reset",
            description = "Creates a short-lived password reset token (hashed in DB) and triggers MessagingClient delivery. " +
                    "Always returns neutral 202 to avoid account enumeration."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "202",
                    description = "Request accepted (neutral response).",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AcceptedResponseDto.class),
                            examples = @ExampleObject(value = "{\"message\":\"If the account exists, further instructions were sent.\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":400,\"code\":\"VALIDATION_ERROR\",\"message\":\"Request validation failed\",\"path\":\"/api/v1/auth/password/forgot\"}")
                    )
            )
    })
    public ResponseEntity<AcceptedResponseDto> passwordForgot(@Valid @RequestBody PasswordForgotRequestDto request) {
        credentialRecoveryService.initiatePasswordForgot(request.getEmail());
        return ResponseEntity.accepted()
                .body(new AcceptedResponseDto("If the account exists, further instructions were sent."));
    }

    @PostMapping("/password/reset")
    @Operation(
            summary = "Reset password",
            description = "Consumes a valid password reset token, updates password hash and marks token as used."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Password successfully reset.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LogoutResponseDto.class),
                            examples = @ExampleObject(value = "{\"message\":\"Password reset successful\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid/expired token or malformed request.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":410,\"code\":\"TOKEN_EXPIRED\",\"message\":\"Reset token is expired or already used\",\"path\":\"/api/v1/auth/password/reset\"}")
                    )
            )
    })
    public ResponseEntity<LogoutResponseDto> passwordReset(@Valid @RequestBody PasswordResetRequestDto request) {
        credentialRecoveryService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok(new LogoutResponseDto("Password reset successful"));
    }

    @PostMapping("/mfa/recovery/start")
    @Operation(
            summary = "Start MFA recovery",
            description = "Creates a short-lived MFA recovery token (hashed in DB) and sends it via MessagingClient " +
                    "using the requested channel. Always returns neutral 202."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "202",
                    description = "Request accepted (neutral response).",
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
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":400,\"code\":\"VALIDATION_ERROR\",\"message\":\"Request validation failed\",\"path\":\"/api/v1/auth/mfa/recovery/start\"}")
                    )
            )
    })
    public ResponseEntity<AcceptedResponseDto> mfaRecoveryStart(@Valid @RequestBody MfaRecoveryStartRequestDto request) {
        credentialRecoveryService.startMfaRecovery(request.getEmail(), request.getChannel());
        return ResponseEntity.accepted()
                .body(new AcceptedResponseDto("If recovery is available, instructions were sent."));
    }

    @PostMapping("/mfa/recovery/confirm")
    @Operation(
            summary = "Confirm MFA recovery",
            description = "Consumes a valid MFA recovery token and disables current MFA secret to allow secure re-enrollment."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "MFA recovery confirmed.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LogoutResponseDto.class),
                            examples = @ExampleObject(value = "{\"message\":\"MFA recovery confirmed\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid/expired token.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":400,\"code\":\"TOKEN_INVALID\",\"message\":\"Recovery token is expired or already consumed\",\"path\":\"/api/v1/auth/mfa/recovery/confirm\"}")
                    )
            )
    })
    public ResponseEntity<LogoutResponseDto> mfaRecoveryConfirm(@Valid @RequestBody MfaRecoveryConfirmRequestDto request) {
        credentialRecoveryService.confirmMfaRecovery(request.getToken());
        return ResponseEntity.ok(new LogoutResponseDto("MFA recovery confirmed"));
    }

    private Credential loadCredential(Long credentialId) {
        return credentialRepository.findById(credentialId)
                .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Credential not found"));
    }

    private void cleanupExpiredTransactions() {
        Instant now = Instant.now();
        loginTransactions.entrySet().removeIf(e -> e.getValue().createdAt().plus(LOGIN_TRANSACTION_TTL).isBefore(now));
    }

    private ResponseCookie buildRefreshCookie(String refreshToken, SessionPolicy sessionPolicy) {
        return ResponseCookie.from(REFRESH_COOKIE_NAME, refreshToken)
                .httpOnly(true)
                .secure(false)
                .path("/api/v1/auth")
                .sameSite("Strict")
                .maxAge(Duration.between(Instant.now(), calculateSessionExpiry(sessionPolicy, Instant.now())))
                .build();
    }

    private ResponseCookie clearRefreshCookie() {
        return ResponseCookie.from(REFRESH_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(false)
                .path("/api/v1/auth")
                .sameSite("Strict")
                .maxAge(Duration.ZERO)
                .build();
    }

    private Instant calculateSessionExpiry(SessionPolicy policy, Instant now) {
        if (policy == SessionPolicy.MONTHS_3) {
            return now.plus(90, ChronoUnit.DAYS);
        }
        return now.plus(24, ChronoUnit.HOURS);
    }

    private Optional<String> readCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        for (Cookie cookie : request.getCookies()) {
            if (Objects.equals(cookie.getName(), cookieName)) {
                return Optional.ofNullable(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    private void ensureSamePayload(IdempotencyRecord record, String requestHash) {
        if (!Objects.equals(record.getRequestHash(), requestHash)) {
            throw new AppException(CONFLICT, ErrorCode.IDEMPOTENCY_CONFLICT, "Idempotency-Key already used with a different payload");
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

    private boolean isValidTotp(String code, String secret, Instant now) {
        if (code == null || code.length() != mfaConfig.getTotpDigits()) {
            return false;
        }

        byte[] key = decodeBase32(secret.replace(" ", "").toUpperCase());
        long currentStep = now.getEpochSecond() / mfaConfig.getTotpPeriodSeconds();
        for (int delta = -mfaConfig.getTotpAllowedDriftSteps(); delta <= mfaConfig.getTotpAllowedDriftSteps(); delta++) {
            String generated = generateTotp(key, currentStep + delta, mfaConfig.getTotpDigits());
            if (generated.equals(code)) {
                return true;
            }
        }
        return false;
    }

    private String generateTotp(byte[] key, long counter, int digits) {
        try {
            byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % (int) Math.pow(10, digits);
            return String.format("%0" + digits + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate TOTP", e);
        }
    }

    private byte[] decodeBase32(String value) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0;
        int bitsLeft = 0;
        List<Byte> out = new ArrayList<>();

        for (char c : value.toCharArray()) {
            if (c == '=') {
                break;
            }
            int val = alphabet.indexOf(c);
            if (val < 0) {
                continue;
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.add((byte) ((buffer >> (bitsLeft - 8)) & 0xFF));
                bitsLeft -= 8;
            }
        }

        byte[] result = new byte[out.size()];
        for (int i = 0; i < out.size(); i++) {
            result[i] = out.get(i);
        }
        return result;
    }

    private List<String> splitCsv(String value) {
        return java.util.Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .sorted(Comparator.naturalOrder())
                .toList();
    }

    private record PendingLoginTransaction(Long credentialId, Instant createdAt) {
    }

    private static class MfaVerifyReplayPayload {
        private AccessTokenResponseDto accessToken;
        private String refreshToken;

        public MfaVerifyReplayPayload() {
        }

        public MfaVerifyReplayPayload(AccessTokenResponseDto accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }

        public AccessTokenResponseDto getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(AccessTokenResponseDto accessToken) {
            this.accessToken = accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }
}
