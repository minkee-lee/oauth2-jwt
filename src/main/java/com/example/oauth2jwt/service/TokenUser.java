package com.example.oauth2jwt.service;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenUser {
    // TODO
    private Long userId;
    private String username;
}
