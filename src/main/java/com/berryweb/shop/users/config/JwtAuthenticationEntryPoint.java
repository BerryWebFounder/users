package com.berryweb.shop.users.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {

        log.error("Unauthorized access attempt: {} - {}",
                request.getRequestURI(), authException.getMessage());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        String errorMessage = "인증이 필요합니다.";
        String requestURI = request.getRequestURI();

        // 요청 경로에 따라 메시지 커스터마이징
        if (requestURI.contains("/admin/")) {
            errorMessage = "관리자 권한이 필요합니다.";
        } else if (requestURI.contains("/api/users/me")) {
            errorMessage = "로그인이 필요합니다.";
        }

        String jsonResponse = String.format(
                "{\"error\": \"Unauthorized\", \"message\": \"%s\", \"path\": \"%s\", \"timestamp\": \"%s\"}",
                errorMessage,
                requestURI,
                java.time.Instant.now().toString()
        );

        response.getWriter().write(jsonResponse);
    }

}
