package com.example.oauth2jwt.exception;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class ExceptionEntity {
    private String code;
    private String message;
    private Object detail;

    @Builder
    public ExceptionEntity(String code, String message, Object detail) {
        this.code = code;
        this.message = message;
        this.detail = detail;
    }
}
