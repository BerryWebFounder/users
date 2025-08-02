package com.berryweb.shop.users.service;

import com.berryweb.shop.users.dto.*;
import com.berryweb.shop.users.entity.User;
import com.berryweb.shop.users.entity.UserRole;
import com.berryweb.shop.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // ============ UserDetailsService 구현 ============

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        return userRepository.findByUsernameOrEmail(usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + usernameOrEmail));
    }

    // ============ 사용자 조회 메서드들 ============

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다. ID: " + id));
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        return userRepository.findByUsernameOrEmail(usernameOrEmail);
    }

    public User getUserByUsernameOrEmail(String usernameOrEmail) {
        return findByUsernameOrEmail(usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + usernameOrEmail));
    }

    // ============ 사용자 생성 및 수정 ============

    @Transactional
    public User createUser(UserCreateReq request) {
        log.info("Creating new user: {}", request.getUsername());

        // 유효성 검사
        validateUserCreation(request);

        // 사용자 생성
        User user = new User(
                request.getUsername(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword()),
                request.getFullName()
        );

        // 추가 정보 설정
        if (request.getBio() != null) {
            user.setBio(request.getBio());
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }

        // 이메일 인증 토큰 생성
        user.setEmailVerificationToken(generateEmailVerificationToken());

        User savedUser = userRepository.save(user);
        log.info("User created successfully: {} (ID: {})", savedUser.getUsername(), savedUser.getId());

        return savedUser;
    }

    @Transactional
    public User updateUser(Long id, UserUpdateReq request) {
        log.info("Updating user: {}", id);

        User user = getUserById(id);

        // 이메일 변경 시 중복 검사
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new IllegalArgumentException("이미 사용 중인 이메일입니다: " + request.getEmail());
            }
            user.setEmail(request.getEmail());
            // 이메일이 변경되면 재인증 필요
            user.setEmailVerified(false);
            user.setEmailVerificationToken(generateEmailVerificationToken());
        }

        // 다른 정보 업데이트
        if (request.getFullName() != null) {
            user.setFullName(request.getFullName());
        }
        if (request.getBio() != null) {
            user.setBio(request.getBio());
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        if (request.getAvatarUrl() != null) {
            user.setAvatarUrl(request.getAvatarUrl());
        }

        User updatedUser = userRepository.save(user);
        log.info("User updated successfully: {}", updatedUser.getUsername());

        return updatedUser;
    }

    @Transactional
    public void changePassword(Long userId, PasswordChangeReq request) {
        log.info("Changing password for user: {}", userId);

        User user = getUserById(userId);

        // 현재 비밀번호 확인
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("현재 비밀번호가 일치하지 않습니다.");
        }

        // 새 비밀번호 확인
        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new IllegalArgumentException("새 비밀번호와 확인 비밀번호가 일치하지 않습니다.");
        }

        // 새 비밀번호가 현재 비밀번호와 다른지 확인
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new IllegalArgumentException("새 비밀번호는 현재 비밀번호와 달라야 합니다.");
        }

        // 비밀번호 변경
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        log.info("Password changed successfully for user: {}", userId);
    }

    // ============ 계정 관리 ============

    @Transactional
    public void updateLastLoginTime(Long userId) {
        userRepository.updateLastLoginTime(userId, LocalDateTime.now());
    }

    @Transactional
    public void verifyEmail(String token) {
        log.info("Verifying email with token: {}", token);

        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 이메일 인증 토큰입니다."));

        user.verifyEmail();
        userRepository.save(user);

        log.info("Email verified successfully for user: {}", user.getUsername());
    }

    @Transactional
    public void deactivateUser(Long userId, String reason) {
        log.info("Deactivating user: {} (reason: {})", userId, reason);

        User user = getUserById(userId);
        user.deactivate();
        userRepository.save(user);

        log.info("User deactivated: {}", user.getUsername());
    }

    @Transactional
    public void activateUser(Long userId) {
        log.info("Activating user: {}", userId);

        User user = getUserById(userId);
        user.activate();
        userRepository.save(user);

        log.info("User activated: {}", user.getUsername());
    }

    @Transactional
    public void deleteUser(Long userId) {
        log.info("Deleting user: {}", userId);

        User user = getUserById(userId);
        userRepository.delete(user);

        log.info("User deleted: {}", user.getUsername());
    }

    // ============ 검색 및 목록 조회 ============

    public Page<User> getAllUsers(Pageable pageable) {
        return userRepository.findAllOrderByCreatedAtDesc(pageable);
    }

    public Page<User> getActiveUsers(Pageable pageable) {
        return userRepository.findByIsActive(true, pageable);
    }

    public Page<User> getUsersByRole(UserRole role, Pageable pageable) {
        return userRepository.findByRole(role, pageable);
    }

    public Page<User> searchUsers(String keyword, Pageable pageable) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return getAllUsers(pageable);
        }
        return userRepository.searchUsers(keyword.trim(), pageable);
    }

    public Page<User> searchActiveUsers(String keyword, Pageable pageable) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return getActiveUsers(pageable);
        }
        return userRepository.searchActiveUsers(keyword.trim(), pageable);
    }

    // ============ 관리자 기능 ============

    @Transactional
    public void updateUserRole(Long userId, UserRoleUpdateReq request) {
        log.info("Updating user role: {} to {}", userId, request.getRole());

        User user = getUserById(userId);
        user.changeRole(request.getRole());
        userRepository.save(user);

        log.info("User role updated: {} -> {}", user.getUsername(), request.getRole());
    }

    @Transactional
    public void updateUserStatus(Long userId, UserStatusUpdateReq request) {
        log.info("Updating user status: {} to {}", userId, request.getIsActive());

        User user = getUserById(userId);
        if (request.getIsActive()) {
            user.activate();
        } else {
            user.deactivate();
        }
        userRepository.save(user);

        log.info("User status updated: {} -> {}", user.getUsername(), request.getIsActive());
    }

    public List<User> getAdminUsers() {
        return userRepository.findByRole(UserRole.ADMIN);
    }

    public List<User> getModeratorUsers() {
        return userRepository.findByRole(UserRole.SYSOP);
    }

    public List<User> getStaffUsers() {
        return userRepository.findByRoleIn(List.of(UserRole.ADMIN, UserRole.SYSOP));
    }

    // ============ 통계 ============

    public long getTotalUserCount() {
        return userRepository.count();
    }

    public long getActiveUserCount() {
        return userRepository.countByIsActiveTrue();
    }

    public long getInactiveUserCount() {
        return userRepository.countByIsActiveFalse();
    }

    public long getVerifiedUserCount() {
        return userRepository.countByEmailVerifiedTrue();
    }

    public long getUnverifiedUserCount() {
        return userRepository.countByEmailVerifiedFalse();
    }

    public long getUserCountByRole(UserRole role) {
        return userRepository.countByRole(role);
    }

    public long getTodayRegistrationCount() {
        return userRepository.countTodayRegistrations();
    }

    public long getThisWeekRegistrationCount() {
        return userRepository.countThisWeekRegistrations();
    }

    public long getThisMonthRegistrationCount() {
        return userRepository.countThisMonthRegistrations();
    }

    // ============ 유효성 검사 ============

    private void validateUserCreation(UserCreateReq request) {
        // 사용자명 중복 검사
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("이미 사용 중인 사용자명입니다: " + request.getUsername());
        }

        // 이메일 중복 검사
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다: " + request.getEmail());
        }

        // 비밀번호 확인
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("비밀번호와 확인 비밀번호가 일치하지 않습니다.");
        }
    }

    public boolean isUsernameAvailable(String username) {
        return !userRepository.existsByUsername(username);
    }

    public boolean isEmailAvailable(String email) {
        return !userRepository.existsByEmail(email);
    }

    // ============ 유틸리티 메서드들 ============

    private String generateEmailVerificationToken() {
        return UUID.randomUUID().toString();
    }

    public UserRes toUserRes(User user) {
        return new UserRes(user);
    }

    public List<UserRes> toUserResList(List<User> users) {
        return users.stream()
                .map(UserRes::new)
                .toList();
    }

    // ============ 비밀번호 재설정 ============

    @Transactional
    public void initiatePasswordReset(String email) {
        log.info("Initiating password reset for email: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당 이메일로 등록된 사용자가 없습니다."));

        String resetToken = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(1); // 1시간 후 만료

        user.setPasswordResetToken(resetToken, expiresAt);
        userRepository.save(user);

        // 이메일 발송은 별도 서비스에서 처리
        log.info("Password reset token generated for user: {}", user.getUsername());
    }

    @Transactional
    public void resetPassword(PasswordResetConfirmReq request) {
        log.info("Resetting password with token: {}", request.getToken());

        User user = userRepository.findByValidPasswordResetToken(request.getToken(), LocalDateTime.now())
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않거나 만료된 토큰입니다."));

        // 새 비밀번호 확인
        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new IllegalArgumentException("새 비밀번호와 확인 비밀번호가 일치하지 않습니다.");
        }

        // 비밀번호 변경
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.clearPasswordResetToken();
        userRepository.save(user);

        log.info("Password reset successfully for user: {}", user.getUsername());
    }

}
