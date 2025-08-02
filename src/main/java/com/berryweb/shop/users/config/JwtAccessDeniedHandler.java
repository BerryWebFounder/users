package com.berryweb.shop.users.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException
    ) throws IOException {

        log.warn("Access denied for user: {} - Path: {} - Reason: {}",
                request.getRemoteUser(),
                request.getRequestURI(),
                accessDeniedException.getMessage());

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");

        String errorMessage = "접근 권한이 없습니다.";
        String requestURI = request.getRequestURI();

        // 요청 경로에 따라 메시지 커스터마이징
        if (requestURI.contains("/admin/")) {
            errorMessage = "관리자만 접근할 수 있습니다.";
        } else if (requestURI.contains("/api/users/")) {
            errorMessage = "해당 사용자 정보에 접근할 권한이 없습니다.";
        }

        String jsonResponse = String.format(
                "{\"error\": \"Forbidden\", \"message\": \"%s\", \"path\": \"%s\", \"timestamp\": \"%s\"}",
                errorMessage,
                requestURI,
                java.time.Instant.now().toString()
        );

        response.getWriter().write(jsonResponse);
    }

}
