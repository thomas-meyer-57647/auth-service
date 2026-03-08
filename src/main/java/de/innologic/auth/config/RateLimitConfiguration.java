package de.innologic.auth.config;

import de.innologic.auth.service.RateLimiterService;
import de.innologic.auth.web.filter.RateLimitingInterceptor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class RateLimitConfiguration implements WebMvcConfigurer {

    private final RateLimiterService rateLimiterService;
    private final RateLimitProperties properties;

    public RateLimitConfiguration(RateLimiterService rateLimiterService, RateLimitProperties properties) {
        this.rateLimiterService = rateLimiterService;
        this.properties = properties;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RateLimitingInterceptor(rateLimiterService, properties))
                .order(Ordered.HIGHEST_PRECEDENCE + 5);
    }
}
