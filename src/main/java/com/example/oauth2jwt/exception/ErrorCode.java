package com.example.oauth2jwt.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@ToString
@AllArgsConstructor
public enum ErrorCode {
    AUTHENTICATION_FAIL(HttpStatus.UNAUTHORIZED, "authentication.required", ""),
    SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "server.error", "");

    private HttpStatus status;
    private String code;
    private String message;

}
