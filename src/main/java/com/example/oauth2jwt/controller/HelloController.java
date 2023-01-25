package com.example.oauth2jwt.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/hello")
public class HelloController {

    @GetMapping
    public Object hello(JwtAuthenticationToken a) {
        if (a == null) {
            return "Authentication is null";
        }
        log.info("name: {}", a.getName());
        log.info("claims: {}", a.getToken().getClaims());
        return Map.of("header", a.getToken().getHeaders(),
                "claims", a.getToken().getClaims()
        );
    }
}
