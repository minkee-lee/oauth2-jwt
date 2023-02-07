package com.example.oauth2jwt.config.dev.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class DevAuthenticationProvider implements AuthenticationProvider {
    @Value("${auth.token.generate-key}")
    private String tokenGenerateKey;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String credential = (String) authentication.getCredentials();
        // TODO username, credential 체크
        // - http basic 인증 처리

        // Token 생성 시 http basic 체크
        String decodedKey = new String(Base64.getDecoder().decode(tokenGenerateKey));
        String id = decodedKey.split(":")[0];
        String passwd = decodedKey.split(":")[1];

        log.info("Try authentiate. User: {}", username);
        if (id.equals(username) && passwd.equals(credential)) {
            log.info("http basic authentication success");
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    username , credential, List.of(new SimpleGrantedAuthority("user")));

            return token;
        }

        log.info("Http basic authentication fail");
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
