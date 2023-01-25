package com.example.oauth2jwt.service;


import lombok.*;
import org.apache.tomcat.jni.Local;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@RequiredArgsConstructor
@Builder
public class TokenDto {
    private String tokenValue;
    private String subject;
    private String issuer;
    private LocalDateTime issuedAt;
    private LocalDateTime expiresAt;
}
