package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.service.TokenDto;
import com.example.oauth2jwt.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/auth/token")
    public TokenDto generateToken(@RequestParam("userId") Long userId) {
        // TODO authorization required for API ?
        return tokenService.generateToken(userId);
    }

    @GetMapping("/auth/jwks")
    public String getJwks() {
        return tokenService.getJwks();
    }

    @GetMapping("/auth/userinfo")
    public Object userinfo(JwtAuthenticationToken token) {
        if (token == null) {
            return "Authentication token is null.";
        }
        return token.getToken().getClaims();
    }
}
