package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;

import java.util.List;

@Schema(name = "ServiceTokenRequest", description = "Request payload to issue an internal service token.")
public class ServiceTokenRequestDto {

    @Schema(description = "Name of the calling service.", example = "auth-service", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String serviceName;

    @Schema(description = "Tenant ID under which the service token should be issued.", example = "tenant-1", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String tenantId;

    @Schema(description = "Targets (audience) for the service token.", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotEmpty
    private List<String> aud;

    @Schema(description = "Scopes granted to the service token.", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotEmpty
    private List<String> scopes;

    @Schema(description = "Requested token lifetime in seconds.", example = "300")
    @Positive
    private Long ttlSeconds;

    public ServiceTokenRequestDto() {
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public List<String> getAud() {
        return aud;
    }

    public void setAud(List<String> aud) {
        this.aud = aud;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public Long getTtlSeconds() {
        return ttlSeconds;
    }

    public void setTtlSeconds(Long ttlSeconds) {
        this.ttlSeconds = ttlSeconds;
    }
}
