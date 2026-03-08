package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Response payload for support diagnosis requests.")
public record SupportDiagnosisResponseDto(
        @Schema(description = "Support user that initiated the diagnosis.", example = "support-user-1")
        String supportUserId,
        @Schema(description = "Support role used for the diagnosis.", example = "SUPPORT_AGENT")
        String supportRole,
        @Schema(description = "Tenant identifier provided in the request.", example = "tenant-1")
        String tenantId,
        @Schema(description = "Company identifier provided in the request.", example = "company-1")
        String companyId,
        @Schema(description = "Tenant key provided in the request for alternative lookup.", example = "tenant-key-abc")
        String tenantKey,
        @Schema(description = "Tenant identifier that was actually analyzed.", example = "tenant-1")
        String resolvedTenantId,
        @Schema(description = "Diagnose purpose supplied by the support user.", example = "Investigating registration stalls")
        String diagnosePurpose,
        @Schema(description = "Overall result status of the diagnostic request.", example = "OK")
        String resultStatus,
        @Schema(description = "Correlation id that travels through the request chain.", example = "f47ac10b-58cc-4372-a567-0e02b2c3d479")
        String correlationId,
        @Schema(description = "Aggregated insights returned to support.", implementation = SupportDiagnosisDetails.class)
        SupportDiagnosisDetails details
) {
}
