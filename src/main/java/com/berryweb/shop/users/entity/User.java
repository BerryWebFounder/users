package com.berryweb.shop.users.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    @NotBlank(message = "사용자명은 필수입니다")
    @Size(min = 3, max = 50, message = "사용자명은 3-50자 사이여야 합니다")
    private String username;

    @Column(unique = true, nullable = false, length = 100)
    @NotBlank(message = "이메일은 필수입니다")
    @Email(message = "올바른 이메일 형식이 아닙니다")
    private String email;

    @Column(nullable = false)
    @NotBlank(message = "비밀번호는 필수입니다")
    @Size(min = 8, message = "비밀번호는 최소 8자 이상이어야 합니다")
    @JsonIgnore
    private String password;

    @Column(name = "full_name", nullable = false, length = 100)
    @NotBlank(message = "이름은 필수입니다")
    @Size(max = 100, message = "이름은 100자를 초과할 수 없습니다")
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role = UserRole.USER;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "email_verified", nullable = false)
    private Boolean emailVerified = false;

    @Column(name = "avatar_url", length = 500)
    private String avatarUrl;

    @Column(length = 500)
    private String bio;

    @Column(length = 20)
    private String phone;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "email_verification_token")
    @JsonIgnore
    private String emailVerificationToken;

    @Column(name = "password_reset_token")
    @JsonIgnore
    private String passwordResetToken;

    @Column(name = "password_reset_expires_at")
    @JsonIgnore
    private LocalDateTime passwordResetExpiresAt;

    // 생성자
    public User(String username, String email, String password, String fullName) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.fullName = fullName;
        this.role = UserRole.USER;
        this.isActive = true;
        this.emailVerified = false;
    }

    public User(String username, String email, String password, String fullName, UserRole role) {
        this(username, email, password, fullName);
        this.role = role;
    }

    // UserDetails 구현
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isActive;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isActive && emailVerified;
    }

    // 비즈니스 로직 메서드
    public boolean isAdmin() {
        return role == UserRole.ADMIN;
    }

    public boolean isModerator() {
        return role == UserRole.SYSOP || isAdmin();
    }

    public boolean canManagePosts() {
        return isModerator();
    }

    public boolean canManageUsers() {
        return isAdmin();
    }

    public void updateLastLogin() {
        this.lastLoginAt = LocalDateTime.now();
    }

    public void verifyEmail() {
        this.emailVerified = true;
        this.emailVerificationToken = null;
    }

    public void deactivate() {
        this.isActive = false;
    }

    public void activate() {
        this.isActive = true;
    }

    public void updateProfile(String fullName, String bio, String phone) {
        if (fullName != null && !fullName.trim().isEmpty()) {
            this.fullName = fullName.trim();
        }
        this.bio = bio;
        this.phone = phone;
    }

    public void changeRole(UserRole newRole) {
        this.role = newRole;
    }

    // 비밀번호 재설정 토큰 설정
    public void setPasswordResetToken(String token, LocalDateTime expiresAt) {
        this.passwordResetToken = token;
        this.passwordResetExpiresAt = expiresAt;
    }

    // 비밀번호 재설정 토큰 클리어
    public void clearPasswordResetToken() {
        this.passwordResetToken = null;
        this.passwordResetExpiresAt = null;
    }

    // 비밀번호 재설정 토큰 유효성 검사
    public boolean isPasswordResetTokenValid() {
        return passwordResetToken != null &&
                passwordResetExpiresAt != null &&
                LocalDateTime.now().isBefore(passwordResetExpiresAt);
    }

    // 이메일 인증 토큰 설정
    public void setEmailVerificationToken(String token) {
        this.emailVerificationToken = token;
    }

    // Display용 메서드들
    public String getDisplayName() {
        return fullName != null && !fullName.trim().isEmpty() ? fullName : username;
    }

    public String getRoleDisplayName() {
        return role.getDisplayName();
    }

    public boolean hasAvatar() {
        return avatarUrl != null && !avatarUrl.trim().isEmpty();
    }

    public boolean hasBio() {
        return bio != null && !bio.trim().isEmpty();
    }

    public boolean hasPhone() {
        return phone != null && !phone.trim().isEmpty();
    }

}
