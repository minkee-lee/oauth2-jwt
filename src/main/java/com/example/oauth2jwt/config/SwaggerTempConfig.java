package com.example.oauth2jwt.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import springfox.documentation.oas.web.OpenApiTransformationContext;
import springfox.documentation.oas.web.WebMvcOpenApiTransformationFilter;
import springfox.documentation.spi.DocumentationType;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * swagger-ui 에서 server 설정이 안되는 이슈용  W/A
 */

@Component
public class SwaggerTempConfig implements WebMvcOpenApiTransformationFilter {
    @Value("${swagger.server.url}")
    private String serverUrl;

    @Override
    public OpenAPI transform(OpenApiTransformationContext<HttpServletRequest> context) {
        OpenAPI openAPI = context.getSpecification();

        Server server = new Server();
        server.setUrl(serverUrl);
        openAPI.setServers(List.of(server));
        return openAPI;
    }

    @Override
    public boolean supports(DocumentationType documentationType) {
        return documentationType.equals(DocumentationType.OAS_30);
    }
}
