package com.berryweb.shop.users.controller;

import com.berryweb.shop.users.dto.PasswordChangeReq;
import com.berryweb.shop.users.dto.UserRes;
import com.berryweb.shop.users.dto.UserUpdateReq;
import com.berryweb.shop.users.entity.User;
import com.berryweb.shop.users.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:3001", "http://localhost:8080"})
public class UserController {

    private final UserService userService;

    // ============ 내 정보 관리 ============

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getMyProfile(@AuthenticationPrincipal User currentUser) {
        log.info("Get profile request for user: {}", currentUser.getUsername());

        try {
            UserRes userRes = userService.toUserRes(currentUser);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", userRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Get profile failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "프로필 조회에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    @PutMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> updateMyProfile(
            @AuthenticationPrincipal User currentUser,
            @Valid @RequestBody UserUpdateReq request) {
        log.info("Update profile request for user: {}", currentUser.getUsername());

        try {
            User updatedUser = userService.updateUser(currentUser.getId(), request);
            UserRes userRes = userService.toUserRes(updatedUser);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "프로필이 업데이트되었습니다.");
            response.put("data", userRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Update profile failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    @PutMapping("/me/password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> changePassword(
            @AuthenticationPrincipal User currentUser,
            @Valid @RequestBody PasswordChangeReq request) {
        log.info("Change password request for user: {}", currentUser.getUsername());

        try {
            userService.changePassword(currentUser.getId(), request);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "비밀번호가 변경되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Change password failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    @DeleteMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> deleteMyAccount(@AuthenticationPrincipal User currentUser) {
        log.info("Delete account request for user: {}", currentUser.getUsername());

        try {
            userService.deleteUser(currentUser.getId());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "계정이 삭제되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Delete account failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "계정 삭제에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 다른 사용자 정보 조회 ============

    @GetMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getUserById(@PathVariable Long id) {
        log.info("Get user request for ID: {}", id);

        try {
            User user = userService.getUserById(id);
            UserRes userRes = userService.toUserRes(user);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", userRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Get user failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "사용자를 찾을 수 없습니다.");

            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/username/{username}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getUserByUsername(@PathVariable String username) {
        log.info("Get user request for username: {}", username);

        try {
            User user = userService.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
            UserRes userRes = userService.toUserRes(user);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", userRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Get user by username failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "사용자를 찾을 수 없습니다.");

            return ResponseEntity.notFound().build();
        }
    }

    // ============ 사용자 검색 (운영자/관리자 전용) ============

    @GetMapping("/search")
    @PreAuthorize("hasAnyRole('SYSOP', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> searchUsers(
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {

        log.info("Search users request - keyword: {}, page: {}, size: {}", keyword, page, size);

        try {
            Sort.Direction direction = sortDir.equalsIgnoreCase("desc") ?
                    Sort.Direction.DESC : Sort.Direction.ASC;
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

            Page<User> userPage;
            if (keyword != null && !keyword.trim().isEmpty()) {
                userPage = userService.searchUsers(keyword, pageable);
            } else {
                userPage = userService.getAllUsers(pageable);
            }

            Page<UserRes> userResPage = userPage.map(userService::toUserRes);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", userResPage);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Search users failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "사용자 검색에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/list")
    @PreAuthorize("hasAnyRole('SYSOP', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserList(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir,
            @RequestParam(required = false) Boolean isActive) {

        log.info("Get user list request - page: {}, size: {}, active: {}", page, size, isActive);

        try {
            Sort.Direction direction = sortDir.equalsIgnoreCase("desc") ?
                    Sort.Direction.DESC : Sort.Direction.ASC;
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

            Page<User> userPage;
            if (isActive != null) {
                userPage = userService.getActiveUsers(pageable);
            } else {
                userPage = userService.getAllUsers(pageable);
            }

            Page<UserRes> userResPage = userPage.map(userService::toUserRes);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", userResPage);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Get user list failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "사용자 목록 조회에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 사용자 통계 (운영자/관리자 전용) ============

    @GetMapping("/stats")
    @PreAuthorize("hasAnyRole('SYSOP', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserStats() {
        log.info("Get user stats request");

        try {
            Map<String, Object> stats = new HashMap<>();
            stats.put("totalUsers", userService.getTotalUserCount());
            stats.put("activeUsers", userService.getActiveUserCount());
            stats.put("inactiveUsers", userService.getInactiveUserCount());
            stats.put("verifiedUsers", userService.getVerifiedUserCount());
            stats.put("unverifiedUsers", userService.getUnverifiedUserCount());
            stats.put("todayRegistrations", userService.getTodayRegistrationCount());
            stats.put("thisWeekRegistrations", userService.getThisWeekRegistrationCount());
            stats.put("thisMonthRegistrations", userService.getThisMonthRegistrationCount());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", stats);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Get user stats failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "통계 조회에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 중복 검사 (공개) ============

    @GetMapping("/check-availability")
    public ResponseEntity<Map<String, Object>> checkAvailability(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email) {

        try {
            Map<String, Boolean> availability = new HashMap<>();

            if (username != null && !username.trim().isEmpty()) {
                availability.put("usernameAvailable", userService.isUsernameAvailable(username));
            }

            if (email != null && !email.trim().isEmpty()) {
                availability.put("emailAvailable", userService.isEmailAvailable(email));
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", availability);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Check availability failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "중복 검사 중 오류가 발생했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 계정 상태 관리 (본인만) ============

    @PutMapping("/me/deactivate")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> deactivateMyAccount(@AuthenticationPrincipal User currentUser) {
        log.info("Deactivate account request for user: {}", currentUser.getUsername());

        try {
            userService.deactivateUser(currentUser.getId(), "User requested deactivation");

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "계정이 비활성화되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Deactivate account failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "계정 비활성화에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    @PutMapping("/me/activate")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> activateMyAccount(@AuthenticationPrincipal User currentUser) {
        log.info("Activate account request for user: {}", currentUser.getUsername());

        try {
            userService.activateUser(currentUser.getId());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "계정이 활성화되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Activate account failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "계정 활성화에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 헬스 체크 ============

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "users-service");
        response.put("endpoint", "users");
        response.put("timestamp", java.time.Instant.now().toString());

        return ResponseEntity.ok(response);
    }

}
