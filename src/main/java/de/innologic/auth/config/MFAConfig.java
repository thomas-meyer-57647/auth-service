package de.innologic.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MFAConfig {

    private final int totpDigits;
    private final int totpPeriodSeconds;
    private final int totpAllowedDriftSteps;

    public MFAConfig(
            @Value("${auth.mfa.totp.digits:6}") int totpDigits,
            @Value("${auth.mfa.totp.period-seconds:30}") int totpPeriodSeconds,
            @Value("${auth.mfa.totp.allowed-drift-steps:1}") int totpAllowedDriftSteps
    ) {
        this.totpDigits = totpDigits;
        this.totpPeriodSeconds = totpPeriodSeconds;
        this.totpAllowedDriftSteps = totpAllowedDriftSteps;
    }

    public int getTotpDigits() {
        return totpDigits;
    }

    public int getTotpPeriodSeconds() {
        return totpPeriodSeconds;
    }

    public int getTotpAllowedDriftSteps() {
        return totpAllowedDriftSteps;
    }
}
