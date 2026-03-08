package de.innologic.auth.outbound;

import de.innologic.auth.outbound.dto.CompanyActivationRequest;
import de.innologic.auth.logging.StructuredLogBuilder;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.Instant;

@Component
public class CompanyServiceClient {

    private static final Logger log = LoggerFactory.getLogger(CompanyServiceClient.class);

    private final RestTemplate restTemplate;
    private final String baseUrl;

    public CompanyServiceClient(RestTemplate restTemplate,
                                @Value("${AUTH_COMPANY_SERVICE_BASE_URL:}") String baseUrl) {
        this.restTemplate = restTemplate;
        this.baseUrl = sanitize(baseUrl);
    }

    public void activate(CompanyActivationRequest request) {
        ensureConfigured();
        String url = buildUrl("companies/activate");
        Instant start = Instant.now();
        StructuredLogBuilder builder = StructuredLogBuilder.forLogger(log)
                .event("company.activate")
                .targetService("company-service")
                .action("COMPANY_ACTIVATION")
                .requestPath(url)
                .httpMethod("POST")
                .correlationId(correlationId())
                .field("companyId", request.getCompanyId());
        try {
            restTemplate.postForEntity(url, request, Void.class);
            builder.duration(Duration.between(start, Instant.now()))
                    .outcome("SUCCESS")
                    .info("Company service activated");
        } catch (RestClientException e) {
            builder.duration(Duration.between(start, Instant.now()))
                    .outcome("FAILURE")
                    .errorCode(ErrorCode.DOWNSTREAM_COMPANY_UNAVAILABLE.name())
                    .error("Company service activation failed", e);
            throw new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.DOWNSTREAM_COMPANY_UNAVAILABLE, "Company service unavailable");
        }
    }

    private void ensureConfigured() {
        if (!StringUtils.hasText(baseUrl)) {
            throw new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.DOWNSTREAM_COMPANY_UNAVAILABLE, "Company service base URL not configured");
        }
    }

    private String buildUrl(String path) {
        return baseUrl.endsWith("/") ? baseUrl + path : baseUrl + "/" + path;
    }

    private String sanitize(String value) {
        return value == null ? "" : value.trim();
    }

    private String correlationId() {
        String correlationId = MDC.get(CorrelationIdFilter.MDC_KEY);
        return correlationId == null ? "n/a" : correlationId;
    }
}
