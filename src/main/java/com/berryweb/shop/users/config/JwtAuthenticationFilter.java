package com.berryweb.shop.users.config;

import com.berryweb.shop.users.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            // Authorization 헤더에서 JWT 토큰 추출
            final String authHeader = request.getHeader("Authorization");
            final String jwt;
            final String userEmail;

            // JWT 토큰이 없거나 Bearer 형식이 아닌 경우 다음 필터로
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }

            // Bearer 접두어 제거
            jwt = authHeader.substring(7);

            // 토큰에서 사용자 정보 추출
            userEmail = jwtService.extractUsername(jwt);

            // 사용자가 존재하고 아직 인증되지 않은 경우
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // 사용자 정보 로드
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // 토큰 유효성 검사
                if (jwtService.isTokenValid(jwt, userDetails)) {

                    // Access Token인지 확인 (Refresh Token으로는 API 접근 불가)
                    if (!jwtService.isAccessToken(jwt)) {
                        log.warn("Refresh token used for API access: {}", userEmail);
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.setContentType("application/json;charset=UTF-8");
                        response.getWriter().write(
                                "{\"error\": \"Invalid token type\", \"message\": \"Access token required\"}"
                        );
                        return;
                    }

                    // 인증 객체 생성
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    // 요청 세부 정보 설정
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // SecurityContext에 인증 정보 설정
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("JWT authentication successful for user: {}", userEmail);
                    logRequestInfo(request, userEmail);

                } else {
                    log.warn("Invalid JWT token for user: {}", userEmail);
                }
            }

        } catch (Exception e) {
            log.error("JWT authentication error: {}", e.getMessage());

            // 인증 실패 시 SecurityContext 클리어
            SecurityContextHolder.clearContext();

            // 토큰 관련 오류를 클라이언트에 전달
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");

            String errorMessage = "인증에 실패했습니다.";
            if (e.getMessage().contains("expired")) {
                errorMessage = "토큰이 만료되었습니다.";
            } else if (e.getMessage().contains("malformed")) {
                errorMessage = "잘못된 토큰 형식입니다.";
            } else if (e.getMessage().contains("signature")) {
                errorMessage = "토큰 서명이 유효하지 않습니다.";
            }

            String jsonResponse = String.format(
                    "{\"error\": \"Authentication failed\", \"message\": \"%s\", \"timestamp\": \"%s\"}",
                    errorMessage,
                    java.time.Instant.now().toString()
            );

            response.getWriter().write(jsonResponse);
            return;
        }

        // 다음 필터 실행
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        // JWT 인증을 건너뛸 경로들
        return path.startsWith("/api/auth/") ||
                path.startsWith("/api/users/check-availability") ||
                path.startsWith("/api/users/verify-email") ||
                path.startsWith("/api/health") ||
                path.startsWith("/actuator/") ||
                path.equals("/") ||
                path.startsWith("/static/") ||
                path.startsWith("/css/") ||
                path.startsWith("/js/") ||
                path.startsWith("/images/") ||
                path.startsWith("/favicon.ico") ||
                path.startsWith("/error");
    }

    /**
     * 토큰에서 사용자 ID 추출 (로깅/추적용)
     */
    private Long extractUserIdFromToken(String token) {
        try {
            return jwtService.extractUserId(token);
        } catch (Exception e) {
            log.debug("Failed to extract user ID from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 토큰에서 사용자 역할 추출 (로깅/추적용)
     */
    private String extractUserRoleFromToken(String token) {
        try {
            return jwtService.extractUserRole(token);
        } catch (Exception e) {
            log.debug("Failed to extract user role from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 요청 정보 로깅 (디버깅용)
     */
    private void logRequestInfo(HttpServletRequest request, String username) {
        if (log.isDebugEnabled()) {
            log.debug("JWT Authentication - User: {}, Method: {}, URI: {}, IP: {}",
                    username,
                    request.getMethod(),
                    request.getRequestURI(),
                    getClientIpAddress(request));
        }
    }

    /**
     * 클라이언트 IP 주소 추출
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty() && !"unknown".equalsIgnoreCase(xRealIP)) {
            return xRealIP;
        }

        return request.getRemoteAddr();
    }

}