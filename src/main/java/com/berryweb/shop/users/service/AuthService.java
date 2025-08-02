package com.berryweb.shop.users.service;

import com.berryweb.shop.users.dto.*;
import com.berryweb.shop.users.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // ============ 회원가입 ============

    public UserRes register(UserCreateReq request) {
        log.info("Registering new user: {}", request.getUsername());

        try {
            // 사용자 생성
            User user = userService.createUser(request);

            // 이메일 인증 메일 발송 (추후 구현)
            sendEmailVerification(user);

            log.info("User registered successfully: {}", user.getUsername());
            return userService.toUserRes(user);

        } catch (Exception e) {
            log.error("User registration failed for username: {} - {}", request.getUsername(), e.getMessage());
            throw new RuntimeException("회원가입에 실패했습니다: " + e.getMessage(), e);
        }
    }

    // ============ 로그인 ============

    public LoginRes login(LoginReq request) {
        log.info("User login attempt: {}", request.getUsernameOrEmail());

        try {
            // 사용자 인증
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsernameOrEmail(),
                            request.getPassword()
                    )
            );

            User user = (User) authentication.getPrincipal();

            // 계정 상태 확인
            validateUserAccount(user);

            // JWT 토큰 생성
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            // 마지막 로그인 시간 업데이트
            user.updateLastLogin();
            userService.updateLastLoginTime(user.getId());

            log.info("User logged in successfully: {} (ID: {})", user.getUsername(), user.getId());

            // 응답 생성
            return new LoginRes(
                    accessToken,
                    refreshToken,
                    jwtService.getJwtConfig().get("accessTokenExpiration"),
                    userService.toUserRes(user)
            );

        } catch (AuthenticationException e) {
            log.warn("Login failed for user: {} - {}", request.getUsernameOrEmail(), e.getMessage());
            throw new BadCredentialsException("아이디 또는 비밀번호가 잘못되었습니다.");
        } catch (Exception e) {
            log.error("Login error for user: {} - {}", request.getUsernameOrEmail(), e.getMessage());
            throw new RuntimeException("로그인 중 오류가 발생했습니다.", e);
        }
    }

    // ============ 토큰 갱신 ============

    public LoginRes refreshToken(String refreshToken) {
        log.info("Refreshing token");

        try {
            // 리프레시 토큰 유효성 검사
            if (!jwtService.isRefreshToken(refreshToken)) {
                throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
            }

            if (jwtService.isTokenExpired(refreshToken)) {
                throw new IllegalArgumentException("만료된 리프레시 토큰입니다.");
            }

            // 사용자 정보 추출
            String username = jwtService.extractUsername(refreshToken);
            User user = userService.getUserByUsernameOrEmail(username);

            // 계정 상태 확인
            validateUserAccount(user);

            // 토큰 유효성 재검사
            if (!jwtService.isTokenValid(refreshToken, user)) {
                throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
            }

            // 새 토큰 생성
            String newAccessToken = jwtService.generateAccessToken(user);
            String newRefreshToken = jwtService.generateRefreshToken(user);

            log.info("Token refreshed successfully for user: {}", user.getUsername());

            return new LoginRes(
                    newAccessToken,
                    newRefreshToken,
                    jwtService.getJwtConfig().get("accessTokenExpiration"),
                    userService.toUserRes(user)
            );

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            throw new RuntimeException("토큰 갱신에 실패했습니다: " + e.getMessage(), e);
        }
    }

    // ============ 로그아웃 ============

    public void logout(String token) {
        log.info("User logout");

        try {
            // 토큰 정보 추출
            String username = jwtService.extractUsername(token);
            log.info("User logged out: {}", username);

            // TODO: 토큰 블랙리스트 처리 (Redis 등 사용)
            // blacklistService.addToBlacklist(token);

        } catch (Exception e) {
            log.error("Logout error: {}", e.getMessage());
            // 로그아웃 실패는 클라이언트에 영향을 주지 않도록 처리
        }
    }

    // ============ 이메일 인증 ============

    public void verifyEmail(EmailVerificationReq request) {
        log.info("Verifying email with token: {}", request.getToken());

        try {
            userService.verifyEmail(request.getToken());
            log.info("Email verification successful");

        } catch (Exception e) {
            log.error("Email verification failed: {}", e.getMessage());
            throw new RuntimeException("이메일 인증에 실패했습니다: " + e.getMessage(), e);
        }
    }

    public void resendEmailVerification(String email) {
        log.info("Resending email verification for: {}", email);

        try {
            User user = userService.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("해당 이메일로 등록된 사용자가 없습니다."));

            if (user.getEmailVerified()) {
                throw new IllegalArgumentException("이미 인증된 이메일입니다.");
            }

            // 새 인증 토큰 생성
            user.setEmailVerificationToken(java.util.UUID.randomUUID().toString());

            // 이메일 발송
            sendEmailVerification(user);

            log.info("Email verification resent for user: {}", user.getUsername());

        } catch (Exception e) {
            log.error("Failed to resend email verification: {}", e.getMessage());
            throw new RuntimeException("이메일 재발송에 실패했습니다: " + e.getMessage(), e);
        }
    }

    // ============ 비밀번호 재설정 ============

    public void initiatePasswordReset(PasswordResetReq request) {
        log.info("Initiating password reset for email: {}", request.getEmail());

        try {
            userService.initiatePasswordReset(request.getEmail());

            // 비밀번호 재설정 이메일 발송 (추후 구현)
            // emailService.sendPasswordResetEmail(user, resetToken);

            log.info("Password reset initiated for email: {}", request.getEmail());

        } catch (Exception e) {
            log.error("Password reset initiation failed: {}", e.getMessage());
            // 보안상 이메일 존재 여부를 노출하지 않음
            log.info("Password reset email sent (if user exists)");
        }
    }

    public void confirmPasswordReset(PasswordResetConfirmReq request) {
        log.info("Confirming password reset");

        try {
            userService.resetPassword(request);
            log.info("Password reset completed successfully");

        } catch (Exception e) {
            log.error("Password reset confirmation failed: {}", e.getMessage());
            throw new RuntimeException("비밀번호 재설정에 실패했습니다: " + e.getMessage(), e);
        }
    }

    // ============ 사용자 정보 조회 ============

    public UserRes getCurrentUser(String token) {
        try {
            String username = jwtService.extractUsername(token);
            User user = userService.getUserByUsernameOrEmail(username);
            return userService.toUserRes(user);

        } catch (Exception e) {
            log.error("Failed to get current user: {}", e.getMessage());
            throw new RuntimeException("사용자 정보 조회에 실패했습니다.", e);
        }
    }

    // ============ 토큰 유효성 검사 ============

    public boolean validateToken(String token) {
        try {
            if (jwtService.isTokenExpired(token)) {
                return false;
            }

            String username = jwtService.extractUsername(token);
            User user = userService.getUserByUsernameOrEmail(username);

            return jwtService.isTokenValid(token, user) && user.isEnabled();

        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    // ============ 계정 상태 확인 ============

    private void validateUserAccount(User user) {
        if (!user.getIsActive()) {
            log.warn("Login attempt by inactive user: {}", user.getUsername());
            throw new DisabledException("비활성화된 계정입니다. 관리자에게 문의하세요.");
        }

        if (!user.getEmailVerified()) {
            log.warn("Login attempt by unverified user: {}", user.getUsername());
            throw new DisabledException("이메일 인증이 필요합니다. 인증 메일을 확인해주세요.");
        }
    }

    // ============ 보안 검사 ============

    public Map<String, Object> getSecurityInfo(User user) {
        Map<String, Object> securityInfo = new HashMap<>();
        securityInfo.put("userId", user.getId());
        securityInfo.put("username", user.getUsername());
        securityInfo.put("email", user.getEmail());
        securityInfo.put("role", user.getRole());
        securityInfo.put("isActive", user.getIsActive());
        securityInfo.put("emailVerified", user.getEmailVerified());
        securityInfo.put("lastLoginAt", user.getLastLoginAt());
        securityInfo.put("createdAt", user.getCreatedAt());
        return securityInfo;
    }

    public boolean hasPermission(User user, String permission) {
        return switch (permission) {
            case "MANAGE_USERS" -> user.canManageUsers();
            case "MANAGE_POSTS" -> user.canManagePosts();
            case "MODERATE_CONTENT" -> user.isModerator();
            case "ACCESS_ADMIN" -> user.isAdmin();
            default -> false;
        };
    }

    // ============ 외부 서비스 연동 (추후 구현) ============

    private void sendEmailVerification(User user) {
        // TODO: 이메일 서비스 연동
        log.info("Email verification token generated for user: {} (token: {})",
                user.getUsername(), user.getEmailVerificationToken());
    }

    private void sendPasswordResetEmail(User user, String resetToken) {
        // TODO: 이메일 서비스 연동
        log.info("Password reset token generated for user: {} (token: {})",
                user.getUsername(), resetToken);
    }

    // ============ 사용자명/이메일 중복 검사 ============

    public Map<String, Boolean> checkAvailability(String username, String email) {
        Map<String, Boolean> availability = new HashMap<>();

        if (username != null && !username.trim().isEmpty()) {
            availability.put("usernameAvailable", userService.isUsernameAvailable(username));
        }

        if (email != null && !email.trim().isEmpty()) {
            availability.put("emailAvailable", userService.isEmailAvailable(email));
        }

        return availability;
    }

    // ============ 계정 잠금 관련 (추후 구현) ============

    public void lockAccount(Long userId, String reason) {
        // TODO: 계정 잠금 기능 구현
        log.info("Account locked for user: {} (reason: {})", userId, reason);
    }

    public void unlockAccount(Long userId) {
        // TODO: 계정 잠금 해제 기능 구현
        log.info("Account unlocked for user: {}", userId);
    }

}
