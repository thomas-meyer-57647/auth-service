package de.innologic.auth.config;

import de.innologic.auth.web.filter.CorrelationIdFilter;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.tags.Tag;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openApi() {
        return new OpenAPI()
                .info(new Info().title("Auth Service API").version("v1"))
                .tags(List.of(new Tag().name("Auth").description("Authentication endpoints")));
    }

    @Bean
    public GroupedOpenApi authApiGroup(OperationCustomizer authTagCustomizer,
                                       @Value("${server.servlet.context-path:/api/v1}") String contextPath) {
        String normalized = normalizeContextPath(contextPath);
        String pathPattern = normalized.isBlank() ? "/**" : normalized + "/**";
        return GroupedOpenApi.builder()
                .group("auth")
                .pathsToMatch(pathPattern)
                .addOperationCustomizer(authTagCustomizer)
                .addOperationCustomizer(defaultErrorResponsesCustomizer())
                .build();
    }

    @Bean
    public OperationCustomizer authTagCustomizer() {
        return (operation, handlerMethod) -> {
            operation.setTags(List.of("Auth"));
            return operation;
        };
    }

    @Bean
    public OperationCustomizer defaultErrorResponsesCustomizer() {
        return (operation, handlerMethod) -> {
            addCorrelationHeader(operation);
            ApiResponse errorResponse = new ApiResponse()
                    .description("Standard error response")
                    .content(new Content().addMediaType(
                            "application/json",
                            new MediaType().schema(new Schema<>().$ref("#/components/schemas/ApiError"))
                    ));
            operation.getResponses().addApiResponse("400", operation.getResponses().get("400") == null ? errorResponse : operation.getResponses().get("400"));
            operation.getResponses().addApiResponse("401", operation.getResponses().get("401") == null ? errorResponse : operation.getResponses().get("401"));
            operation.getResponses().addApiResponse("403", operation.getResponses().get("403") == null ? errorResponse : operation.getResponses().get("403"));
            operation.getResponses().addApiResponse("500", operation.getResponses().get("500") == null ? errorResponse : operation.getResponses().get("500"));
            return operation;
        };
    }

    private void addCorrelationHeader(Operation operation) {
        if (operation.getParameters() == null || operation.getParameters().stream()
                .noneMatch(parameter -> CorrelationIdFilter.HEADER_NAME.equals(parameter.getName()))) {
            operation.addParametersItem(correlationHeaderParameter());
        }
    }

    private Parameter correlationHeaderParameter() {
        return new Parameter()
                .in("header")
                .name(CorrelationIdFilter.HEADER_NAME)
                .description("Correlation Id sent by the caller; generated when missing.")
                .required(false)
                .schema(new StringSchema().example("92e2653b-cd23-40b9-a71f-1c3fbd24f973"));
    }

    private static String normalizeContextPath(String contextPath) {
        if (contextPath == null || contextPath.isBlank() || "/".equals(contextPath)) {
            return "";
        }
        String trimmed = contextPath.endsWith("/") ? contextPath.substring(0, contextPath.length() - 1) : contextPath;
        return trimmed.isBlank() ? "" : trimmed;
    }
}
