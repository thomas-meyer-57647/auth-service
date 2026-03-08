package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Map;

@Schema(description = "Support diagnosis metrics for technical troubleshooting.")
public record SupportDiagnosisDetails(
        @Schema(description = "Total number of registration processes for the tenant.", example = "3")
        long totalRegistrations,
        @Schema(description = "Registration processes that still need email verification.", example = "1")
        long pendingRegistrations,
        @Schema(description = "Registration processes that have verified the email.", example = "1")
        long emailVerifiedRegistrations,
        @Schema(description = "Registration processes that are active.", example = "1")
        long activeRegistrations,
        @Schema(description = "Timestamp of the most recent registration activity for the tenant.", example = "2026-03-08T12:34:56.000Z")
        java.time.Instant lastActivity,
        @Schema(description = "Current request counts stored in the rate limiter per endpoint.", example = "{\"registration-start\": 2}")
        Map<String, Integer> rateLimiterBucketSizes
) {
}
