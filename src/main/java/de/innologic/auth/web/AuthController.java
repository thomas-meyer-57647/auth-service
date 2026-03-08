package de.innologic.auth.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import de.innologic.auth.config.MFAConfig;
import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.IdempotencyRecord;
import de.innologic.auth.domain.entity.MfaConfig;
import de.innologic.auth.domain.entity.RefreshSession;
import de.innologic.auth.domain.enums.SessionPolicy;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.domain.repository.MfaConfigRepository;
import de.innologic.auth.logging.StructuredLogBuilder;
import de.innologic.auth.security.jwt.JwtTokenService;
import de.innologic.auth.service.CredentialRecoveryService;
import de.innologic.auth.service.SessionService;
import de.innologic.auth.web.dto.AcceptedResponseDto;
import de.innologic.auth.web.dto.AccessTokenResponseDto;
import de.innologic.auth.domain.enums.Provider;
import de.innologic.auth.domain.enums.RecoveryChannel;
import de.innologic.auth.service.SocialAuthService;
import de.innologic.auth.web.dto.LoginRequestDto;
import de.innologic.auth.web.dto.LoginResponseDto;
import de.innologic.auth.web.dto.PasswordChangeRequestDto;
import de.innologic.auth.web.dto.SocialLoginRequestDto;
import de.innologic.auth.web.dto.LogoutResponseDto;
import de.innologic.auth.web.dto.MfaVerifyRequestDto;
import de.innologic.auth.web.dto.PasswordForgotRequestDto;
import de.innologic.auth.web.dto.PasswordResetRequestDto;
import de.innologic.auth.web.error.ApiErrorDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
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
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.function.Supplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@RestController
@RequestMapping(path = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "Auth", description = "Authentication endpoints for login, MFA verify, refresh and logout.")
public class AuthController {

    private static final String REFRESH_COOKIE_NAME = "AUTH_REFRESH";
    private static final Duration LOGIN_TRANSACTION_TTL = Duration.ofMinutes(5);
    private static final Duration IDEMPOTENCY_TTL = Duration.ofHours(24);
    private static final String AUTHORIZATION_BEARER_PREFIX = "Bearer ";
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String TENANT_HEADER = "X-Tenant-Id";
    private static final String AUTH_COOKIE_BASE_PATH = "/auth";

    private final CredentialRepository credentialRepository;
    private final MfaConfigRepository mfaRepository;
    private final IdempotencyRepository idempotencyRepository;
    private final JwtTokenService jwtTokenService;
    private final SessionService sessionService;
    private final CredentialRecoveryService credentialRecoveryService;
    private final MFAConfig mfaConfig;
    private final ObjectMapper objectMapper;
    private final SocialAuthService socialAuthService;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final Map<String, PendingLoginTransaction> loginTransactions = new ConcurrentHashMap<>();

    private final String defaultTenantId;
    private final List<String> defaultAudiences;
    private final List<String> defaultScopes;
    private final Duration accessTokenTtl;

    public AuthController(
            CredentialRepository credentialRepository,
            MfaConfigRepository mfaRepository,
            IdempotencyRepository idempotencyRepository,
            JwtTokenService jwtTokenService,
            SessionService sessionService,
            CredentialRecoveryService credentialRecoveryService,
            MFAConfig mfaConfig,
            ObjectMapper objectMapper,
            SocialAuthService socialAuthService,
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
        this.socialAuthService = socialAuthService;
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
            @Parameter(description = "Tenant context for the login request.", required = false, example = "tenant-42")
            @RequestHeader(value = TENANT_HEADER, required = false) String tenantHeader,
            @Valid @RequestBody LoginRequestDto request
    ) {
        String requestHash = hash("login|" + request.getEmail() + "|" + request.getPassword());
        String tenantId = resolveTenantId(tenantHeader);
        Instant start = Instant.now();
        return processLoginRequest(idempotencyKey, requestHash, start, "auth.login.password", "/auth/login", tenantId, () -> {
            AuthCredential credential = credentialRepository.findByLoginEmail(request.getEmail())
                    .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Invalid e-mail or password"));
            if (credential.getPasswordHash() == null || !passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
                throw new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Invalid e-mail or password");
            }
            return createLoginTransaction(credential, tenantId);
        });
    }

    private ResponseEntity<LoginResponseDto> processLoginRequest(String idempotencyKey,
                                                                 String requestHash,
                                                                 Instant start,
                                                                 String eventName,
                                                                 String requestPath,
                                                                 String tenantId,
                                                                 Supplier<LoginResponseDto> action) {
        try {
            Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
            if (existing.isPresent()) {
                IdempotencyRecord record = existing.get();
                ensureSamePayload(record, requestHash);
                if (record.getResponseBody() != null) {
                    HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
                    LoginResponseDto cached = fromJson(record.getResponseBody(), LoginResponseDto.class);
                    logAuthEvent(start, eventName, requestPath, replayStatus, "REPLAY", idempotencyKey, tenantId, cached.getLoginTransactionId(), null)
                            .info("Login transaction replayed");
                    return ResponseEntity.status(replayStatus)
                            .body(cached);
                }
            }

            LoginResponseDto response = action.get();
            upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, HttpStatus.OK.value(), toJson(response));
            logAuthEvent(start, eventName, requestPath, HttpStatus.OK, "SUCCESS", idempotencyKey, tenantId, response.getLoginTransactionId(), null)
                    .info("Login transaction completed");
            return ResponseEntity.ok(response);
        } catch (AppException ex) {
            logAuthEvent(start, eventName, requestPath, ex.getStatus(), "FAILURE", idempotencyKey, tenantId, null, ex.getErrorCode())
                    .warn("Login transaction failed");
            throw ex;
        } catch (RuntimeException ex) {
            logAuthEvent(start, eventName, requestPath, HttpStatus.INTERNAL_SERVER_ERROR, "FAILURE", idempotencyKey, tenantId, null, null)
                    .error("Login transaction failed unexpectedly", ex);
            throw ex;
        }
    }

    private LoginResponseDto createLoginTransaction(AuthCredential credential, String tenantId) {
        String loginTransactionId = "ltx_" + UUID.randomUUID().toString().replace("-", "");
        loginTransactions.put(loginTransactionId, new PendingLoginTransaction(credential.getId(), Instant.now(), tenantId));
        return new LoginResponseDto(loginTransactionId);
    }

    @PostMapping("/social/google")
    @Operation(summary = "Start social login via Google", description = "Creates a login transaction by validating a Google identity.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Login transaction created.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = LoginResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation failed.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Social authentication failed or identity not linked.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "503",
                    description = "Social provider unavailable.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<LoginResponseDto> socialLoginGoogle(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "ltx-social-google-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Parameter(description = "Tenant context for the social login request.", required = false, example = "tenant-42")
            @RequestHeader(value = TENANT_HEADER, required = false) String tenantHeader,
            @Valid @RequestBody SocialLoginRequestDto request
    ) {
        String requestHash = hash("social-login|google|" + request.getSocialToken());
        String tenantId = resolveTenantId(tenantHeader);
        Instant start = Instant.now();
        return processLoginRequest(idempotencyKey, requestHash, start, "auth.login.social.google", "/auth/social/google", tenantId,
                () -> createLoginTransaction(socialAuthService.resolveCredentialForLogin(Provider.GOOGLE, request.getSocialToken()), tenantId)
        );
    }

    @PostMapping("/social/facebook")
    @Operation(summary = "Start social login via Facebook", description = "Creates a login transaction by validating a Facebook identity.")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Login transaction created.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = LoginResponseDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation failed.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Social authentication failed or identity not linked.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            ),
            @ApiResponse(
                    responseCode = "503",
                    description = "Social provider unavailable.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiErrorDto.class))
            )
    })
    public ResponseEntity<LoginResponseDto> socialLoginFacebook(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "ltx-social-facebook-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Parameter(description = "Tenant context for the social login request.", required = false, example = "tenant-42")
            @RequestHeader(value = TENANT_HEADER, required = false) String tenantHeader,
            @Valid @RequestBody SocialLoginRequestDto request
    ) {
        String requestHash = hash("social-login|facebook|" + request.getSocialToken());
        String tenantId = resolveTenantId(tenantHeader);
        Instant start = Instant.now();
        return processLoginRequest(idempotencyKey, requestHash, start, "auth.login.social.facebook", "/auth/social/facebook", tenantId,
                () -> createLoginTransaction(socialAuthService.resolveCredentialForLogin(Provider.FACEBOOK, request.getSocialToken()), tenantId)
        );
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
        Instant start = Instant.now();
        String requestHash = hash("mfa|" + request.getLoginTransactionId() + "|" + request.getTotpCode() + "|" + request.getSessionPolicy());

        try {
            Optional<IdempotencyRecord> existing = idempotencyRepository.findByIdempotencyKey(idempotencyKey);
            if (existing.isPresent()) {
                IdempotencyRecord record = existing.get();
                ensureSamePayload(record, requestHash);
                if (record.getResponseBody() != null) {
                    HttpStatus replayStatus = record.getResponseStatus() == null ? HttpStatus.OK : HttpStatus.valueOf(record.getResponseStatus());
                    MfaVerifyReplayPayload replay = fromJson(record.getResponseBody(), MfaVerifyReplayPayload.class);
                    logAuthEvent(start, "auth.mfa.verify", "/auth/mfa/verify", replayStatus, "REPLAY", idempotencyKey, null, request.getLoginTransactionId(), null)
                            .info("MFA verification replayed");
                    return ResponseEntity.status(replayStatus)
                            .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(replay.getRefreshToken(), request.getSessionPolicy(), httpRequest.getContextPath()).toString())
                            .body(replay.getAccessToken());
                }
            }

            cleanupExpiredTransactions();
            PendingLoginTransaction pending = loginTransactions.remove(request.getLoginTransactionId());
            if (pending == null || pending.createdAt().plus(LOGIN_TRANSACTION_TTL).isBefore(Instant.now())) {
                throw new AppException(BAD_REQUEST, ErrorCode.TOKEN_INVALID, "Invalid or expired loginTransactionId");
            }
            String tenantId = pending.tenantId();

            MfaConfig mfa = mfaRepository.findByCredentialId(pending.credentialId())
                    .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.MFA_REQUIRED, "MFA enrollment missing"));

            if (!mfa.isEnabled() || mfa.getTotpSecretEncrypted() == null || mfa.getTotpSecretEncrypted().isBlank()) {
                throw new AppException(UNAUTHORIZED, ErrorCode.MFA_REQUIRED, "MFA is not enabled");
            }

            if (!isValidTotp(request.getTotpCode(), mfa.getTotpSecretEncrypted(), Instant.now())) {
                throw new AppException(BAD_REQUEST, ErrorCode.TOTP_INVALID, "Invalid TOTP code");
            }

            SessionService.SessionWithToken sessionWithToken = sessionService.createSession(
                    loadCredential(pending.credentialId()),
                    request.getSessionPolicy(),
                    pending.tenantId(),
                    httpRequest.getRemoteAddr(),
                    httpRequest.getHeader(HttpHeaders.USER_AGENT)
            );
            RefreshSession session = sessionWithToken.session();
            String refreshToken = sessionWithToken.refreshToken();

            String accessToken = jwtTokenService.issueAccessToken(
                    pending.credentialId(),
                    tenantForSession(session),
                    String.valueOf(session.getId()),
                    defaultAudiences,
                    defaultScopes,
                    List.of("pwd", "totp")
            );

            AccessTokenResponseDto response = new AccessTokenResponseDto(accessToken, "Bearer", accessTokenTtl.toSeconds());
            MfaVerifyReplayPayload replayPayload = new MfaVerifyReplayPayload(response, refreshToken);

            upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash, 200, toJson(replayPayload));

            ResponseEntity<AccessTokenResponseDto> responseEntity = ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(refreshToken, request.getSessionPolicy(), httpRequest.getContextPath()).toString())
                    .body(response);
            logAuthEvent(start, "auth.mfa.verify", "/auth/mfa/verify", HttpStatus.OK, "SUCCESS", idempotencyKey, tenantId, request.getLoginTransactionId(), null)
                    .info("MFA verification completed");
            return responseEntity;
        } catch (AppException ex) {
            logAuthEvent(start, "auth.mfa.verify", "/auth/mfa/verify", ex.getStatus(), "FAILURE", idempotencyKey, null, request.getLoginTransactionId(), ex.getErrorCode())
                    .warn("MFA verification failed");
            throw ex;
        } catch (RuntimeException ex) {
            logAuthEvent(start, "auth.mfa.verify", "/auth/mfa/verify", HttpStatus.INTERNAL_SERVER_ERROR, "FAILURE", idempotencyKey, null, request.getLoginTransactionId(), null)
                    .error("MFA verification failed unexpectedly", ex);
            throw ex;
        }
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
    public ResponseEntity<AccessTokenResponseDto> refresh(
            HttpServletRequest request,
            @Parameter(description = "Tenant context for the refresh request.", required = false, example = "tenant-42")
            @RequestHeader(value = TENANT_HEADER, required = false) String tenantHeader
    ) {
        Instant start = Instant.now();
        try {
            String refreshToken = readCookie(request, REFRESH_COOKIE_NAME)
                    .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.REFRESH_INVALID, "Refresh cookie missing"));

            SessionService.RotationResult rotation = sessionService.rotateRefreshToken(refreshToken);
            RefreshSession session = rotation.session();
            String normalizedTenantHeader = normalizeTenantHeader(tenantHeader);
            ensureTenantMatchesHeader(normalizedTenantHeader, session);

            String tenantId = tenantForSession(session);
            String accessToken = jwtTokenService.issueAccessToken(
                    session.getCredential().getId(),
                    tenantId,
                    String.valueOf(session.getId()),
                    defaultAudiences,
                    defaultScopes,
                    List.of("refresh")
            );

            AccessTokenResponseDto responseBody = new AccessTokenResponseDto(accessToken, "Bearer", accessTokenTtl.toSeconds());
            ResponseEntity<AccessTokenResponseDto> response = ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(rotation.newRefreshToken(), session.getSessionPolicy(), request.getContextPath()).toString())
                    .body(responseBody);
            logAuthEvent(start, "auth.refresh", "/auth/refresh", HttpStatus.OK, "SUCCESS", null, tenantId, null, null)
                    .info("Refresh completed");
            return response;
        } catch (AppException ex) {
            logAuthEvent(start, "auth.refresh", "/auth/refresh", ex.getStatus(), "FAILURE", null, null, null, ex.getErrorCode())
                    .warn("Refresh failed");
            throw ex;
        } catch (RuntimeException ex) {
            logAuthEvent(start, "auth.refresh", "/auth/refresh", HttpStatus.INTERNAL_SERVER_ERROR, "FAILURE", null, null, null, null)
                    .error("Refresh failed unexpectedly", ex);
            throw ex;
        }
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
        Instant start = Instant.now();
        try {
            readCookie(request, REFRESH_COOKIE_NAME).ifPresent(sessionService::revokeSessionByRefreshToken);
            ResponseEntity<LogoutResponseDto> response = ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, clearRefreshCookie(request.getContextPath()).toString())
                    .body(new LogoutResponseDto("Logged out"));
            logAuthEvent(start, "auth.logout", "/auth/logout", HttpStatus.OK, "SUCCESS", null, null, null, null)
                    .info("Logout completed");
            return response;
        } catch (AppException ex) {
            logAuthEvent(start, "auth.logout", "/auth/logout", ex.getStatus(), "FAILURE", null, null, null, ex.getErrorCode())
                    .warn("Logout failed");
            throw ex;
        } catch (RuntimeException ex) {
            logAuthEvent(start, "auth.logout", "/auth/logout", HttpStatus.INTERNAL_SERVER_ERROR, "FAILURE", null, null, null, null)
                    .error("Logout failed unexpectedly", ex);
            throw ex;
        }
    }

    @PostMapping("/password/forgot")
    @Operation(
            summary = "Start password reset",
            description = "Creates a short-lived password reset token (hashed in DB) and triggers MessagingClient delivery. " +
                    "Always returns neutral 202 to avoid account enumeration. Requires Idempotency-Key header."
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
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Idempotency-Key reused with different payload.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class)
                    )
            )
    })
    public ResponseEntity<AcceptedResponseDto> passwordForgot(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "password-forgot-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody PasswordForgotRequestDto request
    ) {
        String requestHash = hash("password-forgot|" + request.getEmail() + "|" + request.getChannel());
        Instant start = Instant.now();
        return processIdempotentResponse(
                start,
                "auth.password.forgot",
                "/auth/password/forgot",
                idempotencyKey,
                requestHash,
                AcceptedResponseDto.class,
                () -> {
                    credentialRecoveryService.initiatePasswordForgot(request.getEmail(), request.getChannel());
                    return ResponseEntity.accepted().body(new AcceptedResponseDto("If the account exists, further instructions were sent."));
                }
        );
    }

    @PostMapping("/password/reset")
    @Operation(
            summary = "Reset password",
            description = "Consumes a valid password reset token, updates password hash and marks token as used. Requires Idempotency-Key header."
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
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Idempotency-Key reused with different payload.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class)
                    )
            )
    })
    public ResponseEntity<LogoutResponseDto> passwordReset(
            @Parameter(description = "Idempotency key for safe retries.", required = true, example = "password-reset-1")
            @NotBlank @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody PasswordResetRequestDto request
    ) {
        String tokenFingerprint = hash(request.getToken());
        String passwordFingerprint = hash(request.getNewPassword());
        String requestHash = hash("password-reset|" + tokenFingerprint + "|" + passwordFingerprint);
        Instant start = Instant.now();
        return processIdempotentResponse(
                start,
                "auth.password.reset",
                "/auth/password/reset",
                idempotencyKey,
                requestHash,
                LogoutResponseDto.class,
                () -> {
                    credentialRecoveryService.resetPassword(request.getToken(), request.getNewPassword());
                    return ResponseEntity.ok(new LogoutResponseDto("Password reset successful"));
                }
        );
    }

    @PostMapping("/password/change")
    @Operation(
            summary = "Change password",
            description = "Changes the password for an authenticated credential. Requires a valid Bearer access token."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "202",
                    description = "Password change accepted.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AcceptedResponseDto.class),
                            examples = @ExampleObject(value = "{\"message\":\"Password changed successfully\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation or request format error.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":400,\"code\":\"VALIDATION_ERROR\",\"message\":\"Request validation failed\",\"path\":\"/api/v1/auth/password/change\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Missing or invalid authorization token.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiErrorDto.class),
                            examples = @ExampleObject(value = "{\"timestamp\":\"2026-02-18T12:34:56Z\",\"status\":401,\"code\":\"INVALID_CREDENTIALS\",\"message\":\"Invalid credentials\",\"path\":\"/api/v1/auth/password/change\"}")
                    )
            )
    })
    public ResponseEntity<AcceptedResponseDto> passwordChange(
            @Valid @RequestBody PasswordChangeRequestDto request,
            HttpServletRequest httpRequest
    ) {
        Instant start = Instant.now();
        try {
            long credentialId = credentialIdFromAccessToken(httpRequest);
            credentialRecoveryService.changePassword(credentialId, request.getCurrentPassword(), request.getNewPassword());
            ResponseEntity<AcceptedResponseDto> response = ResponseEntity.accepted().body(new AcceptedResponseDto("Password changed successfully"));
            logAuthEvent(start, "auth.password.change", "/auth/password/change", HttpStatus.ACCEPTED, "SUCCESS", null, null, null, null)
                    .info("Password change completed");
            return response;
        } catch (AppException ex) {
            logAuthEvent(start, "auth.password.change", "/auth/password/change", ex.getStatus(), "FAILURE", null, null, null, ex.getErrorCode())
                    .warn("Password change failed");
            throw ex;
        } catch (RuntimeException ex) {
            logAuthEvent(start, "auth.password.change", "/auth/password/change", HttpStatus.INTERNAL_SERVER_ERROR, "FAILURE", null, null, null, null)
                    .error("Password change failed unexpectedly", ex);
            throw ex;
        }
    }

    private AuthCredential loadCredential(Long credentialId) {
        return credentialRepository.findById(credentialId)
                .orElseThrow(() -> new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Credential not found"));
    }

    private void cleanupExpiredTransactions() {
        Instant now = Instant.now();
        loginTransactions.entrySet().removeIf(e -> e.getValue().createdAt().plus(LOGIN_TRANSACTION_TTL).isBefore(now));
    }

    private ResponseCookie buildRefreshCookie(String refreshToken, SessionPolicy sessionPolicy, String contextPath) {
        Instant now = Instant.now();
        return ResponseCookie.from(REFRESH_COOKIE_NAME, refreshToken)
                .httpOnly(true)
                .secure(false)
                .path(resolveCookiePath(contextPath))
                .sameSite("Strict")
                .maxAge(Duration.between(now, calculateSessionExpiry(sessionPolicy, now)))
                .build();
    }

    private ResponseCookie clearRefreshCookie(String contextPath) {
        return ResponseCookie.from(REFRESH_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(false)
                .path(resolveCookiePath(contextPath))
                .sameSite("Strict")
                .maxAge(Duration.ZERO)
                .build();
    }

    private String resolveCookiePath(String contextPath) {
        String normalized = contextPath == null ? "" : contextPath.trim();
        if (normalized.equals("/")) {
            normalized = "";
        }
        if (!normalized.isBlank() && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized + AUTH_COOKIE_BASE_PATH;
    }

    private Instant calculateSessionExpiry(SessionPolicy policy, Instant now) {
        if (policy == SessionPolicy.MONTHS_3) {
            return now.plus(90, ChronoUnit.DAYS);
        }
        return now.plus(24, ChronoUnit.HOURS);
    }

    private String normalizeTenantHeader(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private String resolveTenantId(String headerValue) {
        String normalized = normalizeTenantHeader(headerValue);
        return normalized != null ? normalized : defaultTenantId;
    }

    private void ensureTenantMatchesHeader(String headerValue, RefreshSession session) {
        if (headerValue == null) {
            return;
        }
        if (!headerValue.equals(session.getTenantId())) {
            throw new AppException(HttpStatus.FORBIDDEN, ErrorCode.TENANT_MISMATCH, "Tenant mismatch between header and session");
        }
    }

    private String tenantForSession(RefreshSession session) {
        String tenantId = session.getTenantId();
        return (tenantId == null || tenantId.isBlank()) ? defaultTenantId : tenantId;
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

    private String correlationId() {
        String value = MDC.get(CorrelationIdFilter.MDC_KEY);
        return value == null ? "n/a" : value;
    }

    private StructuredLogBuilder logAuthEvent(Instant start,
                                               String eventName,
                                               String requestPath,
                                               HttpStatus status,
                                               String outcome,
                                               String idempotencyKey,
                                               String tenantId,
                                               String loginTransactionId,
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
                .field("tenantId", tenantId)
                .field("loginTransactionId", loginTransactionId);
        if (errorCode != null) {
            builder.errorCode(errorCode.name());
        }
        return builder;
    }

    private HttpStatus toHttpStatus(HttpStatusCode statusCode) {
        if (statusCode == null) {
            return HttpStatus.OK;
        }
        HttpStatus resolved = HttpStatus.resolve(statusCode.value());
        return resolved != null ? resolved : HttpStatus.valueOf(statusCode.value());
    }

    private void ensureSamePayload(IdempotencyRecord record, String requestHash) {
        if (!Objects.equals(record.getRequestHash(), requestHash)) {
            throw new AppException(CONFLICT, ErrorCode.IDEMPOTENCY_CONFLICT, "Idempotency-Key already used with a different payload");
        }
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
                logAuthEvent(start, eventName, requestPath, replayStatus, "REPLAY", idempotencyKey, null, null, null)
                        .info("Idempotent action replayed");
                return ResponseEntity.status(replayStatus).body(body);
            }

            ResponseEntity<T> response = action.get();
            upsertIdempotencyRecord(existing.orElseGet(IdempotencyRecord::new), idempotencyKey, requestHash,
                    response.getStatusCodeValue(), toJson(response.getBody()));
            HttpStatus successStatus = toHttpStatus(response.getStatusCode());
            logAuthEvent(start, eventName, requestPath, successStatus, "SUCCESS", idempotencyKey, null, null, null)
                    .info("Idempotent action completed");
            return response;
        } catch (AppException ex) {
            logAuthEvent(start, eventName, requestPath, ex.getStatus(), "FAILURE", idempotencyKey, null, null, ex.getErrorCode())
                    .warn("Idempotent action failed");
            throw ex;
        } catch (RuntimeException ex) {
            logAuthEvent(start, eventName, requestPath, HttpStatus.INTERNAL_SERVER_ERROR, "FAILURE", idempotencyKey, null, null, null)
                    .error("Idempotent action failed unexpectedly", ex);
            throw ex;
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

    private long credentialIdFromAccessToken(HttpServletRequest request) {
        String headerValue = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (headerValue == null || !headerValue.startsWith(AUTHORIZATION_BEARER_PREFIX)) {
            throw new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Missing or invalid Authorization header");
        }
        String token = headerValue.substring(AUTHORIZATION_BEARER_PREFIX.length()).trim();
        if (token.isBlank()) {
            throw new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Missing bearer token");
        }

        JWTClaimsSet claims = jwtTokenService.validateAccessToken(token);
        try {
            return Long.parseLong(claims.getSubject());
        } catch (NumberFormatException e) {
            throw new AppException(UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Invalid credential subject in access token");
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

    private record PendingLoginTransaction(Long credentialId, Instant createdAt, String tenantId) {
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
