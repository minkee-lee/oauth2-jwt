package com.example.oauth2jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    /**
     * 토큰 생성요청에 대해서는 http basic 인증 적용 -> DevAuthenticationProvider 에서 처리
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain tokenSecurityFilterChain(HttpSecurity http) throws Exception {
        RequestMatcher requestMatcher = request -> {
            boolean isMatch = new AntPathMatcher().match("/api/v1/auth/token/**", request.getRequestURI());
            return isMatch;
        };
        http.sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.requestMatcher(requestMatcher).authorizeRequests(authorize -> {
            authorize.mvcMatchers("/api/v1/auth/token/**").authenticated();
//            authorize.mvcMatchers("/api/v1/auth/token/**").permitAll();
        }).csrf(csrf -> csrf
                .ignoringRequestMatchers(requestMatcher)
        ).exceptionHandling(exception -> exception
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
        ).httpBasic();
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.headers().frameOptions().sameOrigin(); // h2-console 접근 시 X-Frame-Options deny 이슈 해결
        http.csrf().disable();

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource())
                ).authorizeRequests(authorize -> {
                    authorize
                            .mvcMatchers("/swagger-ui/**", "/v3/api-docs", "/swagger-resources/**").permitAll()
                            .mvcMatchers("/h2-console").permitAll()
                            .mvcMatchers("/health").permitAll()
                            .mvcMatchers("/api/v1/auth/**").permitAll()
                            .anyRequest().authenticated();
                })
                .oauth2ResourceServer(oauth2 -> {
                    oauth2.authenticationEntryPoint(new CustomAuthenticationEntryPoint());
                    oauth2.jwt();
                })
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*");
        // swagger-ui 에서 oauth2 code 로그인을 위해  token 요청 시 전달
        corsConfiguration.addAllowedHeader("x-requested-with");
        corsConfiguration.addAllowedHeader("authorization");
        corsConfiguration.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/oauth2/token", corsConfiguration);
        return source;
    }
}
