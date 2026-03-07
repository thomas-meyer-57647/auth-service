package de.innologic.auth.domain.entity;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.enums.RecoveryChannel;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "mfa_configs")
public class MfaConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "credential_id", nullable = false, unique = true)
    private AuthCredential credential;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "totp_secret_encrypted", length = 512)
    private String totpSecretEncrypted;

    @Column(name = "second_factor_type", length = 32)
    private String secondFactorType;

    @Column(name = "email_channel_enabled", nullable = false)
    private boolean emailChannelEnabled;

    @Column(name = "sms_channel_enabled", nullable = false)
    private boolean smsChannelEnabled;

    @Enumerated(EnumType.STRING)
    @Column(name = "recovery_channel", length = 16)
    private RecoveryChannel recoveryChannel;

    @Column(name = "phone_number", length = 32)
    private String phoneNumber;

    @Column(name = "enrolled_at")
    private Instant enrolledAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "modified_at", nullable = false)
    private Instant updatedAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public AuthCredential getCredential() {
        return credential;
    }

    public void setCredential(AuthCredential credential) {
        this.credential = credential;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getSecondFactorType() {
        return secondFactorType;
    }

    public void setSecondFactorType(String secondFactorType) {
        this.secondFactorType = secondFactorType;
    }

    public boolean isEmailChannelEnabled() {
        return emailChannelEnabled;
    }

    public void setEmailChannelEnabled(boolean emailChannelEnabled) {
        this.emailChannelEnabled = emailChannelEnabled;
    }

    public boolean isSmsChannelEnabled() {
        return smsChannelEnabled;
    }

    public void setSmsChannelEnabled(boolean smsChannelEnabled) {
        this.smsChannelEnabled = smsChannelEnabled;
    }

    public String getTotpSecretEncrypted() {
        return totpSecretEncrypted;
    }

    public void setTotpSecretEncrypted(String totpSecretEncrypted) {
        this.totpSecretEncrypted = totpSecretEncrypted;
    }

    public RecoveryChannel getRecoveryChannel() {
        return recoveryChannel;
    }

    public void setRecoveryChannel(RecoveryChannel recoveryChannel) {
        this.recoveryChannel = recoveryChannel;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public Instant getEnrolledAt() {
        return enrolledAt;
    }

    public void setEnrolledAt(Instant enrolledAt) {
        this.enrolledAt = enrolledAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
