package de.innologic.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.tags.Tag;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
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
    public GroupedOpenApi authApiGroup(OperationCustomizer authTagCustomizer) {
        return GroupedOpenApi.builder()
                .group("auth")
                .pathsToMatch("/api/v1/auth/**")
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
}
