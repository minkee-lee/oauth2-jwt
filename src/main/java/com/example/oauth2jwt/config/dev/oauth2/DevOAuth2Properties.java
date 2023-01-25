package com.example.oauth2jwt.config.dev.oauth2;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "dev.oauth2")
public class DevOAuth2Properties {
    private String clientId;
    private String clientSecret;
    private List<String> redirectUris;
}
