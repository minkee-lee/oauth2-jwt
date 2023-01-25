package com.example.oauth2jwt.config.dev.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Slf4j
@Configuration
@ConditionalOnProperty(
        value = "dev.oauth2.enabled",
        havingValue = "true",
        matchIfMissing = false
)
@RequiredArgsConstructor
public class DevSecurityConfig {
    private final DevOAuth2Properties oauth2Config;
    private final DevAuthenticationProvider authenticationProvider;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        return http.formLogin(Customizer.withDefaults()).build();

        // 토큰 response 에 access-control-allow-origin 을 추가하기 위해 설정 수동 구성
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                .accessTokenResponseHandler(new DevOAuth2TokenSuccessHandler())
        );

        RequestMatcher endpointMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http.requestMatcher(endpointMatcher).authorizeRequests(authorize -> {
            authorize.anyRequest().authenticated();
        }).csrf(csrf -> csrf.ignoringRequestMatchers(endpointMatcher)
        ).exceptionHandling(exception -> exception
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        ).apply(authorizationServerConfigurer);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authenticationProvider);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        String clientId = oauth2Config.getClientId();
        String clientSecret = oauth2Config.getClientSecret();
        List<String> redirectUris = oauth2Config.getRedirectUris();
        log.info("client-id", clientId);
        log.info("client-secret", clientSecret);
        log.info("redirect-uris: {}", redirectUris);

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}" + clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> customizer() {
        return context -> {
            log.info("jwt customizer");
            if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
                OAuth2Authorization oAuth2Authorization = context.getAuthorization();
                if (oAuth2Authorization != null) {
                    OAuth2AuthorizationRequest authorizationRequest =
                            oAuth2Authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
                    if (authorizationRequest != null) {
                        context.getClaims().expiresAt(Instant.now().plus(480, ChronoUnit.MINUTES));
                        context.getClaims().claims(claims -> {
                            claims.put("custom token", "cello");
                            // TODO: cello 개별 속성 추가
                        });
                    }
                }
            }
        };
    }


}
