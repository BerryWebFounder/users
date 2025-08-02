package com.berryweb.shop.users.controller;

import com.berryweb.shop.users.dto.UserRes;
import com.berryweb.shop.users.dto.UserRoleUpdateReq;
import com.berryweb.shop.users.dto.UserStatusUpdateReq;
import com.berryweb.shop.users.entity.User;
import com.berryweb.shop.users.entity.UserRole;
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

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
@CrossOrigin("*")
public class AdminController {

    private final UserService userService;

    // ============ 사용자 목록 관리 ============

    @GetMapping("/users")
    public ResponseEntity<Map<String, Object>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir,
            @RequestParam(required = false) UserRole role,
            @RequestParam(required = false) Boolean isActive,
            @RequestParam(required = false) Boolean emailVerified,
            @RequestParam(required = false) String search) {

        log.info("Admin get users request - page: {}, size: {}, role: {}, active: {}", page, size, role, isActive);

        try {
            Sort.Direction direction = sortDir.equalsIgnoreCase("desc") ?
                    Sort.Direction.DESC : Sort.Direction.ASC;
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

            Page<User> userPage;

            if (search != null && !search.trim().isEmpty()) {
                userPage = userService.searchUsers(search, pageable);
            } else if (role != null) {
                userPage = userService.getUsersByRole(role, pageable);
            } else {
                userPage = userService.getAllUsers(pageable);
            }

            Page<UserRes> userResPage = userPage.map(userService::toUserRes);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", userResPage);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin get users failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "사용자 목록 조회에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<Map<String, Object>> getUserById(@PathVariable Long id) {
        log.info("Admin get user by ID: {}", id);

        try {
            User user = userService.getUserById(id);
            UserRes userRes = userService.toUserRes(user);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", userRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin get user failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "사용자를 찾을 수 없습니다.");

            return ResponseEntity.notFound().build();
        }
    }

    // ============ 사용자 역할 관리 ============

    @PutMapping("/users/{id}/role")
    public ResponseEntity<Map<String, Object>> updateUserRole(
            @PathVariable Long id,
            @Valid @RequestBody UserRoleUpdateReq request,
            @AuthenticationPrincipal User admin) {

        log.info("Admin updating user role: {} to {} by {}", id, request.getRole(), admin.getUsername());

        try {
            // 자신의 역할은 변경할 수 없음
            if (id.equals(admin.getId())) {
                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", "자신의 역할은 변경할 수 없습니다.");

                return ResponseEntity.badRequest().body(response);
            }

            // 대상 사용자 조회
            User targetUser = userService.getUserById(id);

            // 다른 관리자의 역할을 낮출 수는 없음 (보안)
            if (targetUser.isAdmin() && request.getRole() != UserRole.ADMIN) {
                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", "다른 관리자의 권한을 변경할 수 없습니다.");

                return ResponseEntity.badRequest().body(response);
            }

            userService.updateUserRole(id, request);

            User updatedUser = userService.getUserById(id);
            UserRes userRes = userService.toUserRes(updatedUser);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "사용자 역할이 변경되었습니다.");
            response.put("data", userRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin update user role failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 사용자 상태 관리 ============

    @PutMapping("/users/{id}/status")
    public ResponseEntity<Map<String, Object>> updateUserStatus(
            @PathVariable Long id,
            @Valid @RequestBody UserStatusUpdateReq request,
            @AuthenticationPrincipal User admin) {

        log.info("Admin updating user status: {} to {} by {}", id, request.getIsActive(), admin.getUsername());

        try {
            // 자신의 상태는 변경할 수 없음
            if (id.equals(admin.getId())) {
                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", "자신의 상태는 변경할 수 없습니다.");

                return ResponseEntity.badRequest().body(response);
            }

            // 대상 사용자 조회
            User targetUser = userService.getUserById(id);

            // 다른 관리자를 비활성화할 수는 없음
            if (targetUser.isAdmin() && !request.getIsActive()) {
                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", "다른 관리자를 비활성화할 수 없습니다.");

                return ResponseEntity.badRequest().body(response);
            }

            userService.updateUserStatus(id, request);

            User updatedUser = userService.getUserById(id);
            UserRes userRes = userService.toUserRes(updatedUser);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "사용자 상태가 변경되었습니다.");
            response.put("data", userRes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin update user status failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 사용자 삭제 ============

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Map<String, Object>> deleteUser(
            @PathVariable Long id,
            @AuthenticationPrincipal User admin) {

        log.info("Admin deleting user: {} by {}", id, admin.getUsername());

        try {
            // 자신은 삭제할 수 없음
            if (id.equals(admin.getId())) {
                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", "자신의 계정은 삭제할 수 없습니다.");

                return ResponseEntity.badRequest().body(response);
            }

            // 대상 사용자 조회
            User targetUser = userService.getUserById(id);

            // 다른 관리자는 삭제할 수 없음
            if (targetUser.isAdmin()) {
                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", "다른 관리자는 삭제할 수 없습니다.");

                return ResponseEntity.badRequest().body(response);
            }

            userService.deleteUser(id);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "사용자가 삭제되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin delete user failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", e.getMessage());

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 대시보드 통계 ============

    @GetMapping("/dashboard/stats")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        log.info("Admin dashboard stats request");

        try {
            Map<String, Object> stats = new HashMap<>();

            // 기본 통계
            stats.put("totalUsers", userService.getTotalUserCount());
            stats.put("activeUsers", userService.getActiveUserCount());
            stats.put("inactiveUsers", userService.getInactiveUserCount());
            stats.put("verifiedUsers", userService.getVerifiedUserCount());
            stats.put("unverifiedUsers", userService.getUnverifiedUserCount());

            // 가입 통계
            stats.put("todayRegistrations", userService.getTodayRegistrationCount());
            stats.put("thisWeekRegistrations", userService.getThisWeekRegistrationCount());
            stats.put("thisMonthRegistrations", userService.getThisMonthRegistrationCount());

            // 역할별 통계
            Map<String, Long> roleStats = new HashMap<>();
            for (UserRole role : UserRole.values()) {
                roleStats.put(role.name(), userService.getUserCountByRole(role));
            }
            stats.put("roleStats", roleStats);

            // 스태프 목록
            List<UserRes> admins = userService.getAdminUsers().stream()
                    .map(userService::toUserRes)
                    .toList();
            List<UserRes> moderators = userService.getModeratorUsers().stream()
                    .map(userService::toUserRes)
                    .toList();

            Map<String, Object> staff = new HashMap<>();
            staff.put("admins", admins);
            staff.put("moderators", moderators);
            stats.put("staff", staff);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", stats);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin dashboard stats failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "대시보드 통계 조회에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 시스템 정보 ============

    @GetMapping("/system/info")
    public ResponseEntity<Map<String, Object>> getSystemInfo() {
        log.info("Admin system info request");

        try {
            Map<String, Object> systemInfo = new HashMap<>();

            // 시스템 정보
            systemInfo.put("serviceName", "Users Service");
            systemInfo.put("version", "1.0.0");
            systemInfo.put("serverTime", LocalDateTime.now());
            systemInfo.put("javaVersion", System.getProperty("java.version"));
            systemInfo.put("osName", System.getProperty("os.name"));
            systemInfo.put("osVersion", System.getProperty("os.version"));

            // 메모리 정보
            Runtime runtime = Runtime.getRuntime();
            Map<String, Long> memoryInfo = new HashMap<>();
            memoryInfo.put("totalMemory", runtime.totalMemory());
            memoryInfo.put("freeMemory", runtime.freeMemory());
            memoryInfo.put("usedMemory", runtime.totalMemory() - runtime.freeMemory());
            memoryInfo.put("maxMemory", runtime.maxMemory());
            systemInfo.put("memory", memoryInfo);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", systemInfo);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin system info failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "시스템 정보 조회에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 로그 관리 (간단한 버전) ============

    @GetMapping("/logs/recent")
    public ResponseEntity<Map<String, Object>> getRecentLogs(
            @RequestParam(defaultValue = "100") int limit) {

        log.info("Admin recent logs request - limit: {}", limit);

        try {
            // 실제 환경에서는 로그 파일을 읽거나 별도의 로깅 시스템 연동
            Map<String, Object> logInfo = new HashMap<>();
            logInfo.put("message", "로그 조회 기능은 추후 구현 예정입니다.");
            logInfo.put("suggestion", "실제 로그는 서버의 logs/users-service.log 파일을 확인하세요.");

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", logInfo);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin recent logs failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "로그 조회에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============ 일괄 작업 ============

    @PostMapping("/users/bulk-update-status")
    public ResponseEntity<Map<String, Object>> bulkUpdateUserStatus(
            @RequestBody Map<String, Object> request,
            @AuthenticationPrincipal User admin) {

        @SuppressWarnings("unchecked")
        List<Long> userIds = (List<Long>) request.get("userIds");
        Boolean isActive = (Boolean) request.get("isActive");

        log.info("Admin bulk update user status: {} users to {} by {}",
                userIds.size(), isActive, admin.getUsername());

        try {
            int updatedCount = 0;
            int skippedCount = 0;

            for (Long userId : userIds) {
                try {
                    // 자신과 다른 관리자는 제외
                    if (userId.equals(admin.getId())) {
                        skippedCount++;
                        continue;
                    }

                    User targetUser = userService.getUserById(userId);
                    if (targetUser.isAdmin()) {
                        skippedCount++;
                        continue;
                    }

                    UserStatusUpdateReq updateReq = new UserStatusUpdateReq();
                    updateReq.setIsActive(isActive);
                    updateReq.setReason("Bulk update by admin");

                    userService.updateUserStatus(userId, updateReq);
                    updatedCount++;

                } catch (Exception e) {
                    log.warn("Failed to update user {}: {}", userId, e.getMessage());
                    skippedCount++;
                }
            }

            Map<String, Object> result = new HashMap<>();
            result.put("updatedCount", updatedCount);
            result.put("skippedCount", skippedCount);
            result.put("totalCount", userIds.size());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", String.format("일괄 업데이트 완료: %d건 성공, %d건 건너뜀", updatedCount, skippedCount));
            response.put("data", result);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Admin bulk update user status failed: {}", e.getMessage());

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "일괄 업데이트에 실패했습니다.");

            return ResponseEntity.badRequest().body(response);
        }
    }

}
