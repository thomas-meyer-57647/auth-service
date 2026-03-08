package de.innologic.auth.web.filter;

import de.innologic.auth.config.RateLimitProperties;
import de.innologic.auth.service.RateLimiterService;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;

public class RateLimitingInterceptor implements HandlerInterceptor {

    private final RateLimiterService rateLimiterService;
    private final RateLimitProperties properties;

    public RateLimitingInterceptor(RateLimiterService rateLimiterService, RateLimitProperties properties) {
        this.rateLimiterService = rateLimiterService;
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        RateLimitedEndpoint endpoint = RateLimitedEndpoint.fromRequest(request);
        if (endpoint != null) {
            RateLimitProperties.EndpointConfig config = properties.getEndpointConfig(endpoint.getConfigKey());
            int maxRequests = config != null && config.getMaxRequests() > 0 ? config.getMaxRequests() : properties.getDefaultMaxRequests();
            Duration window = config != null && config.getWindow() != null ? config.getWindow() : properties.getDefaultWindow();
            String clientId = deriveClientId(request);
            boolean allowed = rateLimiterService.tryConsume(clientId, endpoint.getConfigKey(), maxRequests, window);
            if (!allowed) {
                throw new AppException(HttpStatus.TOO_MANY_REQUESTS, ErrorCode.RATE_LIMITED, "Rate limit exceeded");
            }
        }
        return true;
    }

    private String deriveClientId(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String remoteAddr = request.getRemoteAddr();
        return remoteAddr == null ? "unknown" : remoteAddr;
    }
}
