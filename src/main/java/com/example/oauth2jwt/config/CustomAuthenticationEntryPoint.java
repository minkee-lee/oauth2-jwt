package com.example.oauth2jwt.config;

import com.example.oauth2jwt.exception.ErrorCode;
import com.example.oauth2jwt.exception.ExceptionEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.entity.ContentType;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Security 인증 실패 시 에러 응답 생성
 */
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error(authException.getMessage());
        ErrorCode errorCode = ErrorCode.AUTHENTICATION_FAIL;
        ExceptionEntity entity = ExceptionEntity.builder()
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .build();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(ContentType.APPLICATION_JSON.toString());
        response.getWriter().print(new ObjectMapper().writeValueAsString(entity));
    }
}
