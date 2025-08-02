package com.berryweb.shop.users.controller;

import com.berryweb.shop.users.dto.*;
import com.berryweb.shop.users.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin("*")
public class AuthController {

    private final AuthService authService;

    // ============ 회원가입 ============

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody UserCreateReq request) {
        log.info("Registration request for username: {}", request.getUsername());

        try {
            UserRes user = authService.register(request);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "회원가입이 완료되었습니다. 이메일 인증을 진행해주세요.");
            response.put("user", user);

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            log.error("Registration failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 로그인 ============

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginReq request) {
        log.info("Login request for: {}", request.getUsernameOrEmail());

        try {
            LoginRes loginRes = authService.login(request);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "로그인이 완료되었습니다.");
            response.put("data", loginRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    // ============ 토큰 갱신 ============

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "리프레시 토큰이 필요합니다.");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            LoginRes loginRes = authService.refreshToken(refreshToken);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "토큰이 갱신되었습니다.");
            response.put("data", loginRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    // ============ 로그아웃 ============

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            authService.logout(token);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "로그아웃이 완료되었습니다.");

        return ResponseEntity.ok(response);
    }

    // ============ 이메일 인증 ============

    @PostMapping("/verify-email")
    public ResponseEntity<Map<String, Object>> verifyEmail(@Valid @RequestBody EmailVerificationReq request) {
        log.info("Email verification request for token: {}", request.getToken());

        try {
            authService.verifyEmail(request);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "이메일 인증이 완료되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Email verification failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, Object>> resendEmailVerification(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        if (email == null || email.trim().isEmpty()) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "이메일 주소가 필요합니다.");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            authService.resendEmailVerification(email);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "인증 이메일이 재발송되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Email verification resend failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 비밀번호 재설정 ============

    @PostMapping("/password-reset")
    public ResponseEntity<Map<String, Object>> initiatePasswordReset(@Valid @RequestBody PasswordResetReq request) {
        log.info("Password reset request for email: {}", request.getEmail());

        try {
            authService.initiatePasswordReset(request);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "비밀번호 재설정 이메일이 발송되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Password reset initiation failed: {}", e.getMessage());

            // 보안상 이메일 존재 여부를 노출하지 않음
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "비밀번호 재설정 이메일이 발송되었습니다.");

            return ResponseEntity.ok(response);
        }
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Map<String, Object>> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmReq request) {
        log.info("Password reset confirmation request");

        try {
            authService.confirmPasswordReset(request);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "비밀번호가 성공적으로 재설정되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Password reset confirmation failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 사용자명/이메일 중복 검사 ============

    @GetMapping("/check-availability")
    public ResponseEntity<Map<String, Object>> checkAvailability(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email) {

        try {
            Map<String, Boolean> availability = authService.checkAvailability(username, email);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", availability);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Availability check failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "중복 검사 중 오류가 발생했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 토큰 유효성 검사 ============

    @PostMapping("/validate-token")
    public ResponseEntity<Map<String, Object>> validateToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("valid", false);
            response.put("message", "토큰이 없습니다.");
            return ResponseEntity.badRequest().body(response);
        }

        String token = authHeader.substring(7);

        try {
            boolean isValid = authService.validateToken(token);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("valid", isValid);

            if (isValid) {
                UserRes user = authService.getCurrentUser(token);
                response.put("user", user);
                response.put("message", "유효한 토큰입니다.");
            } else {
                response.put("message", "유효하지 않은 토큰입니다.");
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("valid", false);
            response.put("message", "토큰 검증 중 오류가 발생했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 현재 사용자 정보 ============

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "인증이 필요합니다.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        String token = authHeader.substring(7);

        try {
            UserRes user = authService.getCurrentUser(token);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", user);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Get current user failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "사용자 정보 조회에 실패했습니다.");

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    // ============ 헬스 체크 ============

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "users-service");
        response.put("timestamp", java.time.Instant.now().toString());

        return ResponseEntity.ok(response);
    }

}
