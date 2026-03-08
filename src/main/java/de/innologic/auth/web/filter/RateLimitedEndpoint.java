package de.innologic.auth.web.filter;

import jakarta.servlet.http.HttpServletRequest;

public enum RateLimitedEndpoint {
    AUTH_LOGIN("/auth/login", "login"),
    AUTH_MFA_VERIFY("/auth/mfa/verify", "mfa-verify"),
    PASSWORD_FORGOT("/password/forgot", "password-forgot"),
    PASSWORD_RESET("/password/reset", "password-reset"),
    REGISTRATION_START("/registration/start", "registration-start"),
    REGISTRATION_SOCIAL_GOOGLE("/registration/social/google", "registration-social-google"),
    REGISTRATION_SOCIAL_FACEBOOK("/registration/social/facebook", "registration-social-facebook"),
    MFA_RECOVERY_START("/mfa/recovery/start", "mfa-recovery-start"),
    MFA_RECOVERY_CONFIRM("/mfa/recovery/confirm", "mfa-recovery-confirm");

    private final String path;
    private final String configKey;

    RateLimitedEndpoint(String path, String configKey) {
        this.path = path;
        this.configKey = configKey;
    }

    public String getPath() {
        return path;
    }

    public String getConfigKey() {
        return configKey;
    }

    public static RateLimitedEndpoint fromRequest(HttpServletRequest request) {
        RateLimitedEndpoint endpoint = fromPath(request.getRequestURI());
        if (endpoint != null) {
            return endpoint;
        }
        String servletPath = request.getServletPath();
        if (servletPath == null) {
            return null;
        }
        return fromPath(servletPath);
    }

    private static RateLimitedEndpoint fromPath(String path) {
        if (path == null) {
            return null;
        }
        String trimmed = path;
        for (RateLimitedEndpoint endpoint : values()) {
            if (trimmed.equalsIgnoreCase(endpoint.path)) {
                return endpoint;
            }
            if (trimmed.endsWith(endpoint.path)) {
                return endpoint;
            }
        }
        return null;
    }
}
