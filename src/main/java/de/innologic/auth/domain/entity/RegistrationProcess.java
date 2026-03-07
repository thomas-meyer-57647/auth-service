package de.innologic.auth.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

@Entity
@Table(
        name = "registration_processes",
        uniqueConstraints = @UniqueConstraint(name = "uk_registration_processes_registration_id", columnNames = "registration_id")
)
public class RegistrationProcess {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "registration_id", nullable = false, length = 64)
    private String registrationId;

    @Column(name = "tenant_id", nullable = false, length = 64)
    private String tenantId;

    @Column(name = "user_id", nullable = false, length = 64)
    private String userId;

    @Column(name = "status", nullable = false, length = 64)
    private String status;

    @Column(name = "company_payload", columnDefinition = "JSON")
    private String companyPayload;

    @Column(name = "location_payload", columnDefinition = "JSON")
    private String locationPayload;

    @Column(name = "user_payload", columnDefinition = "JSON")
    private String userPayload;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "modified_at", nullable = false)
    private Instant modifiedAt;

    // getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCompanyPayload() {
        return companyPayload;
    }

    public void setCompanyPayload(String companyPayload) {
        this.companyPayload = companyPayload;
    }

    public String getLocationPayload() {
        return locationPayload;
    }

    public void setLocationPayload(String locationPayload) {
        this.locationPayload = locationPayload;
    }

    public String getUserPayload() {
        return userPayload;
    }

    public void setUserPayload(String userPayload) {
        this.userPayload = userPayload;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getModifiedAt() {
        return modifiedAt;
    }

    public void setModifiedAt(Instant modifiedAt) {
        this.modifiedAt = modifiedAt;
    }
}
