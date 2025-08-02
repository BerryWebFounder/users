package com.berryweb.shop.users.dto;

import com.berryweb.shop.users.entity.User;
import com.berryweb.shop.users.entity.UserRole;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
public class UserRes {

    private Long id;
    private String username;
    private String email;
    private String fullName;
    private UserRole role;
    private String roleDisplayName;
    private Boolean isActive;
    private Boolean emailVerified;
    private String avatarUrl;
    private String bio;
    private String phone;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastLoginAt;

    // 권한 정보
    private Boolean canManagePosts;
    private Boolean canManageUsers;
    private Boolean canManageComments;
    private Boolean isAdmin;
    private Boolean isModerator;

    public UserRes(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.fullName = user.getFullName();
        this.role = user.getRole();
        this.roleDisplayName = user.getRoleDisplayName();
        this.isActive = user.getIsActive();
        this.emailVerified = user.getEmailVerified();
        this.avatarUrl = user.getAvatarUrl();
        this.bio = user.getBio();
        this.phone = user.getPhone();
        this.createdAt = user.getCreatedAt();
        this.updatedAt = user.getUpdatedAt();
        this.lastLoginAt = user.getLastLoginAt();

        // 권한 정보 설정
        this.canManagePosts = user.canManagePosts();
        this.canManageUsers = user.canManageUsers();
        this.canManageComments = user.getRole().canManageComments();
        this.isAdmin = user.isAdmin();
        this.isModerator = user.isModerator();
    }

    public static UserRes from(User user) {
        return new UserRes(user);
    }

}
