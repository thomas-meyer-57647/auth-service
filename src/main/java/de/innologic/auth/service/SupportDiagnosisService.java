package de.innologic.auth.service;

import de.innologic.auth.domain.entity.RegistrationProcess;
import de.innologic.auth.domain.repository.RegistrationProcessRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
public class SupportDiagnosisService {

    private static final String STATUS_PENDING = "PENDING_EMAIL_VERIFICATION";
    private static final String STATUS_EMAIL_VERIFIED = "EMAIL_VERIFIED";
    private static final String STATUS_ACTIVE = "ACTIVE";

    private final RegistrationProcessRepository registrationProcessRepository;
    private final RateLimiterService rateLimiterService;

    public SupportDiagnosisService(RegistrationProcessRepository registrationProcessRepository,
                                   RateLimiterService rateLimiterService) {
        this.registrationProcessRepository = registrationProcessRepository;
        this.rateLimiterService = rateLimiterService;
    }

    public SupportDiagnosisMetrics collect(String tenantId) {
        long total = registrationProcessRepository.countByTenantId(tenantId);
        long pending = registrationProcessRepository.countByTenantIdAndStatus(tenantId, STATUS_PENDING);
        long verified = registrationProcessRepository.countByTenantIdAndStatus(tenantId, STATUS_EMAIL_VERIFIED);
        long active = registrationProcessRepository.countByTenantIdAndStatus(tenantId, STATUS_ACTIVE);
        Instant lastActivity = registrationProcessRepository.findFirstByTenantIdOrderByModifiedAtDesc(tenantId)
                .map(RegistrationProcess::getModifiedAt)
                .orElse(null);
        Map<String, Integer> rateLimiterBuckets = rateLimiterService.snapshotByEndpoint();
        return new SupportDiagnosisMetrics(total, pending, verified, active, lastActivity, rateLimiterBuckets);
    }

    public record SupportDiagnosisMetrics(
            long totalRegistrations,
            long pendingRegistrations,
            long emailVerifiedRegistrations,
            long activeRegistrations,
            Instant lastActivity,
            Map<String, Integer> rateLimiterBuckets
    ) {
    }
}
