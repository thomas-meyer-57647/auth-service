package de.innologic.auth.config;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "auth.rate-limit")
public class RateLimitProperties {

    @Min(1)
    private int defaultMaxRequests = 20;

    @DurationUnit(ChronoUnit.SECONDS)
    private Duration defaultWindow = Duration.ofSeconds(60);

    private final Map<String, EndpointConfig> endpoints = new LinkedHashMap<>();

    public int getDefaultMaxRequests() {
        return defaultMaxRequests;
    }

    public void setDefaultMaxRequests(int defaultMaxRequests) {
        this.defaultMaxRequests = defaultMaxRequests;
    }

    public Duration getDefaultWindow() {
        return defaultWindow;
    }

    public void setDefaultWindow(Duration defaultWindow) {
        this.defaultWindow = defaultWindow;
    }

    public Map<String, EndpointConfig> getEndpoints() {
        return endpoints;
    }

    public EndpointConfig getEndpointConfig(String key) {
        return endpoints.get(key);
    }

    public static class EndpointConfig {

        @Min(1)
        private int maxRequests;

        @DurationUnit(ChronoUnit.SECONDS)
        private Duration window;

        public int getMaxRequests() {
            return maxRequests;
        }

        public void setMaxRequests(int maxRequests) {
            this.maxRequests = maxRequests;
        }

        public Duration getWindow() {
            return window;
        }

        public void setWindow(Duration window) {
            this.window = window;
        }
    }
}
