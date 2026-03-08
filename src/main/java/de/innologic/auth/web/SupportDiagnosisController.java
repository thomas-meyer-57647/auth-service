package de.innologic.auth.web;

import de.innologic.auth.logging.StructuredLogBuilder;
import de.innologic.auth.service.SupportDiagnosisService;
import de.innologic.auth.service.SupportDiagnosisService.SupportDiagnosisMetrics;
import de.innologic.auth.web.dto.SupportDiagnosisDetails;
import de.innologic.auth.web.dto.SupportDiagnosisResponseDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
@RestController
@RequestMapping(path = "/support", produces = "application/json")
@Validated
@Tag(name = "Support", description = "Support diagnostics and audit tooling")
public class SupportDiagnosisController {

    private static final Logger log = LoggerFactory.getLogger(SupportDiagnosisController.class);
    private static final String ENDPOINT_PATH = "/support/diagnosis";
    private static final String ACTION = "SUPPORT_DIAGNOSIS";

    private final SupportDiagnosisService supportDiagnosisService;

    public SupportDiagnosisController(SupportDiagnosisService supportDiagnosisService) {
        this.supportDiagnosisService = supportDiagnosisService;
    }

    @GetMapping("/diagnosis")
    @Operation(summary = "Support diagnosis", description = "Returns limited technical insights for authorized support staff.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Diagnostic data delivered", content = @Content(schema = @Schema(implementation = SupportDiagnosisResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "Tenant context missing", content = @Content(schema = @Schema(implementation = de.innologic.auth.web.error.ApiErrorDto.class))),
            @ApiResponse(responseCode = "401", description = "Support credentials missing", content = @Content(schema = @Schema(implementation = de.innologic.auth.web.error.ApiErrorDto.class)))
    })
    public SupportDiagnosisResponseDto diagnose(
            @RequestHeader(value = "X-Support-User-Id", required = false)
            @Parameter(in = ParameterIn.HEADER, description = "Identifier of the support user executing the diagnosis.", required = true, example = "support-agent-1")
            String supportUserId,
            @RequestHeader(value = "X-Support-Role", required = false)
            @Parameter(in = ParameterIn.HEADER, description = "Support role or group allowed to perform diagnostics.", required = true, example = "SUPPORT_AGENT")
            String supportRole,
            @RequestHeader(value = "X-Support-Purpose", required = false)
            @Parameter(in = ParameterIn.HEADER, description = "Purpose of the diagnosis request.", required = true, example = "Investigating tenant onboarding")
            String diagnosePurpose,
            @RequestParam(value = "tenantId", required = false)
            @Parameter(description = "Tenant identifier to diagnose.", example = "tenant-1")
            String tenantId,
            @RequestParam(value = "companyId", required = false)
            @Parameter(description = "Company identifier that can be used instead of tenantId.", example = "company-123")
            String companyId,
            @RequestParam(value = "tenantKey", required = false)
            @Parameter(description = "Tenant key that can be used as an alternative lookup.", example = "tenant-key-abc")
            String tenantKey
    ) {
        Instant start = Instant.now();
        if (!isNotBlank(supportUserId) || !isNotBlank(supportRole)) {
            logSupportAudit(start, supportUserId, supportRole, null, tenantId, companyId, tenantKey, diagnosePurpose, "FAILURE", HttpStatus.UNAUTHORIZED, ErrorCode.ACCESS_DENIED);
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.ACCESS_DENIED, "Support credentials missing");
        }
        if (!isNotBlank(diagnosePurpose)) {
            logSupportAudit(start, supportUserId, supportRole, null, tenantId, companyId, tenantKey, diagnosePurpose, "FAILURE", HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR);
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Support purpose must be provided");
        }
        String resolvedTenantId = resolveTenantIdentifier(tenantId, companyId, tenantKey);
        if (resolvedTenantId == null || resolvedTenantId.isBlank()) {
            logSupportAudit(start, supportUserId, supportRole, null, tenantId, companyId, tenantKey, diagnosePurpose, "FAILURE", HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR);
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Provide tenantId, companyId or tenantKey for diagnosis.");
        }

        SupportDiagnosisMetrics metrics = supportDiagnosisService.collect(resolvedTenantId);
        SupportDiagnosisDetails detailsDto = new SupportDiagnosisDetails(
                metrics.totalRegistrations(),
                metrics.pendingRegistrations(),
                metrics.emailVerifiedRegistrations(),
                metrics.activeRegistrations(),
                metrics.lastActivity(),
                metrics.rateLimiterBuckets()
        );
        SupportDiagnosisResponseDto response = new SupportDiagnosisResponseDto(
                supportUserId,
                supportRole,
                tenantId,
                companyId,
                tenantKey,
                resolvedTenantId,
                diagnosePurpose,
                "OK",
                correlationId(),
                detailsDto
        );
        logSupportAudit(start, supportUserId, supportRole, resolvedTenantId, tenantId, companyId, tenantKey, diagnosePurpose, "SUCCESS", HttpStatus.OK, null);
        return response;
    }

    private String resolveTenantIdentifier(String tenantId, String companyId, String tenantKey) {
        if (isNotBlank(tenantId)) {
            return tenantId;
        }
        if (isNotBlank(companyId)) {
            return companyId;
        }
        if (isNotBlank(tenantKey)) {
            return tenantKey;
        }
        return null;
    }

    private boolean isNotBlank(String value) {
        return value != null && !value.isBlank();
    }

    private void logSupportAudit(Instant start,
                                 String supportUserId,
                                 String supportRole,
                                 String resolvedTenantId,
                                 String tenantId,
                                 String companyId,
                                 String tenantKey,
                                 String diagnosePurpose,
                                 String outcome,
                                 HttpStatus status,
                                 ErrorCode errorCode) {
        Duration duration = Duration.between(start, Instant.now());
        StructuredLogBuilder builder = StructuredLogBuilder.forLogger(log)
                .event("support.diagnosis")
                .targetService("auth-service")
                .action(ACTION)
                .requestPath(ENDPOINT_PATH)
                .httpMethod("GET")
                .httpStatus(status.value())
                .duration(duration)
                .outcome(outcome)
                .correlationId(correlationId())
                .field("supportUserId", supportUserId)
                .field("supportRole", supportRole)
                .field("tenantId", tenantId)
                .field("companyId", companyId)
                .field("tenantKey", tenantKey)
                .field("resolvedTenantId", resolvedTenantId)
                .diagnosePurpose(diagnosePurpose);
        if (errorCode != null) {
            builder.errorCode(errorCode.name());
            builder.warn("Support diagnosis access failed");
        } else {
            builder.info("Support diagnosis access succeeded");
        }
    }

    private String correlationId() {
        String value = MDC.get(CorrelationIdFilter.MDC_KEY);
        return value == null ? "n/a" : value;
    }
}
