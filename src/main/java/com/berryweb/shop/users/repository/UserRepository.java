package com.berryweb.shop.users.repository;

import com.berryweb.shop.users.entity.User;
import com.berryweb.shop.users.entity.UserRole;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // ============ 기본 조회 메서드들 ============

    // 사용자명으로 조회
    Optional<User> findByUsername(String username);

    // 이메일로 조회
    Optional<User> findByEmail(String email);

    // 사용자명 또는 이메일로 조회 (로그인용)
    @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
    Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);

    // 사용자명 존재 여부 확인
    boolean existsByUsername(String username);

    // 이메일 존재 여부 확인
    boolean existsByEmail(String email);

    // 활성 사용자만 조회
    List<User> findByIsActiveTrue();

    // 비활성 사용자만 조회
    List<User> findByIsActiveFalse();

    // 이메일 인증된 사용자만 조회
    List<User> findByEmailVerifiedTrue();

    // 이메일 미인증 사용자만 조회
    List<User> findByEmailVerifiedFalse();

    // ============ 역할별 조회 메서드들 ============

    // 특정 역할의 사용자들 조회
    List<User> findByRole(UserRole role);

    // 특정 역할의 사용자들 조회 (페이징)
    Page<User> findByRole(UserRole role, Pageable pageable);

    // 관리자 조회
    List<User> findByRoleIn(List<UserRole> roles);

    // 활성 관리자만 조회
    @Query("SELECT u FROM User u WHERE u.role IN :roles AND u.isActive = true")
    List<User> findActiveUsersByRoles(@Param("roles") List<UserRole> roles);

    // ============ 검색 메서드들 ============

    // 사용자명으로 검색 (부분 일치)
    Page<User> findByUsernameContainingIgnoreCase(String username, Pageable pageable);

    // 이메일로 검색 (부분 일치)
    Page<User> findByEmailContainingIgnoreCase(String email, Pageable pageable);

    // 이름으로 검색 (부분 일치)
    Page<User> findByFullNameContainingIgnoreCase(String fullName, Pageable pageable);

    // 복합 검색 (사용자명, 이메일, 이름)
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.username) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.fullName) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    Page<User> searchUsers(@Param("keyword") String keyword, Pageable pageable);

    // 활성 사용자만 검색
    @Query("SELECT u FROM User u WHERE u.isActive = true AND (" +
            "LOWER(u.username) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.fullName) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<User> searchActiveUsers(@Param("keyword") String keyword, Pageable pageable);

    // ============ 날짜 기반 조회 메서드들 ============

    // 특정 날짜 이후 가입한 사용자들
    List<User> findByCreatedAtAfter(LocalDateTime date);

    // 특정 날짜 이전 가입한 사용자들
    List<User> findByCreatedAtBefore(LocalDateTime date);

    // 특정 기간 가입한 사용자들
    List<User> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    // 최근 로그인한 사용자들
    List<User> findByLastLoginAtAfter(LocalDateTime date);

    // 특정 기간 동안 로그인하지 않은 사용자들
    @Query("SELECT u FROM User u WHERE u.lastLoginAt IS NULL OR u.lastLoginAt < :date")
    List<User> findInactiveUsersSince(@Param("date") LocalDateTime date);

    // ============ 통계 쿼리들 ============

    // 총 사용자 수
    long count();

    // 활성 사용자 수
    long countByIsActiveTrue();

    // 비활성 사용자 수
    long countByIsActiveFalse();

    // 이메일 인증된 사용자 수
    long countByEmailVerifiedTrue();

    // 이메일 미인증 사용자 수
    long countByEmailVerifiedFalse();

    // 역할별 사용자 수
    long countByRole(UserRole role);

    // 특정 기간 가입자 수
    long countByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    // 오늘 가입한 사용자 수
    @Query("SELECT COUNT(u) FROM User u WHERE DATE(u.createdAt) = CURRENT_DATE")
    long countTodayRegistrations();

    // 이번 주 가입한 사용자 수
    @Query("SELECT COUNT(u) FROM User u WHERE WEEK(u.createdAt) = WEEK(CURRENT_DATE) AND YEAR(u.createdAt) = YEAR(CURRENT_DATE)")
    long countThisWeekRegistrations();

    // 이번 달 가입한 사용자 수
    @Query("SELECT COUNT(u) FROM User u WHERE MONTH(u.createdAt) = MONTH(CURRENT_DATE) AND YEAR(u.createdAt) = YEAR(CURRENT_DATE)")
    long countThisMonthRegistrations();

    // ============ 업데이트 쿼리들 ============

    // 마지막 로그인 시간 업데이트
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.id = :userId")
    void updateLastLoginTime(@Param("userId") Long userId, @Param("loginTime") LocalDateTime loginTime);

    // 이메일 인증 상태 업데이트
    @Modifying
    @Query("UPDATE User u SET u.emailVerified = true, u.emailVerificationToken = null WHERE u.id = :userId")
    void verifyEmail(@Param("userId") Long userId);

    // 사용자 활성화/비활성화
    @Modifying
    @Query("UPDATE User u SET u.isActive = :isActive WHERE u.id = :userId")
    void updateUserStatus(@Param("userId") Long userId, @Param("isActive") Boolean isActive);

    // 사용자 역할 변경
    @Modifying
    @Query("UPDATE User u SET u.role = :role WHERE u.id = :userId")
    void updateUserRole(@Param("userId") Long userId, @Param("role") UserRole role);

    // 비밀번호 업데이트
    @Modifying
    @Query("UPDATE User u SET u.password = :password WHERE u.id = :userId")
    void updatePassword(@Param("userId") Long userId, @Param("password") String password);

    // ============ 토큰 관련 쿼리들 ============

    // 이메일 인증 토큰으로 조회
    Optional<User> findByEmailVerificationToken(String token);

    // 비밀번호 재설정 토큰으로 조회
    Optional<User> findByPasswordResetToken(String token);

    // 비밀번호 재설정 토큰 유효성 확인
    @Query("SELECT u FROM User u WHERE u.passwordResetToken = :token AND u.passwordResetExpiresAt > :now")
    Optional<User> findByValidPasswordResetToken(@Param("token") String token, @Param("now") LocalDateTime now);

    // ============ 관리자용 쿼리들 ============

    // 모든 사용자 조회 (페이징, 정렬)
    @Query("SELECT u FROM User u ORDER BY u.createdAt DESC")
    Page<User> findAllOrderByCreatedAtDesc(Pageable pageable);

    // 활성 상태별 사용자 조회
    Page<User> findByIsActive(Boolean isActive, Pageable pageable);

    // 이메일 인증 상태별 사용자 조회
    Page<User> findByEmailVerified(Boolean emailVerified, Pageable pageable);

    // 특정 기간 가입한 사용자들 (페이징)
    Page<User> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);

    // 최근 활동이 없는 사용자들 (페이징)
    @Query("SELECT u FROM User u WHERE u.lastLoginAt IS NULL OR u.lastLoginAt < :date ORDER BY u.lastLoginAt ASC")
    Page<User> findInactiveUsers(@Param("date") LocalDateTime date, Pageable pageable);

    // ============ 일괄 삭제 ============

    // 특정 기간 이전에 가입하고 이메일 미인증인 사용자들 삭제
    @Modifying
    @Query("DELETE FROM User u WHERE u.emailVerified = false AND u.createdAt < :date")
    void deleteUnverifiedUsersBefore(@Param("date") LocalDateTime date);

    // 비활성 사용자들 삭제
    @Modifying
    @Query("DELETE FROM User u WHERE u.isActive = false AND u.updatedAt < :date")
    void deleteInactiveUsersBefore(@Param("date") LocalDateTime date);

}
