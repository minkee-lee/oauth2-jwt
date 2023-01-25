package com.example.oauth2jwt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.builders.RequestParameterBuilder;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.Collections;
import java.util.List;


@Configuration
public class SwaggerConfig {

    @Value("${swagger.server.url}")
    private String serverUrl;

    @Value("${swagger.auth.url}")
    private String authUrl;

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.OAS_30)
                .useDefaultResponseMessages(false)
                .servers(server())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.example.oauth2jwt"))
                .paths(PathSelectors.any())
                .build()
                .ignoredParameterTypes(JwtAuthenticationToken.class)
                .securitySchemes(List.of(
                        httpAuthenticationScheme(),
                        oauth2authorizationCodeScheme())
                )
                .securityContexts(List.of(
                        securityContext()
                ))
                .apiInfo(apiInfo());
    }

    private Server server() {
        return new Server("", serverUrl, "", Collections.emptyList(), Collections.emptyList());
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("title")
                .description("oauth2 서버")
                .version("1.0")
                .build();
    }

    HttpAuthenticationScheme httpAuthenticationScheme() {
        return HttpAuthenticationScheme.JWT_BEARER_BUILDER
                .name("JWT")
                .build();
    }

    private OAuth2Scheme oauth2authorizationCodeScheme() {
        return OAuth2Scheme.OAUTH2_AUTHORIZATION_CODE_FLOW_BUILDER
                .name("oauth2-authorization-code")
                // scope 설정 없으면  ui 에 안나옴
                .scopes(List.of(
                        new AuthorizationScope("openid", "")
                ))
                .authorizationUrl(authUrl + "/oauth2/authorize")
                .tokenUrl(authUrl + "/oauth2/token")
                .build();
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(defaultAuth())
                .build();
    }

    private List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return List.of(
                new SecurityReference("JWT", authorizationScopes),
                new SecurityReference("oauth2-authorization-code", authorizationScopes)
        );
    }

}