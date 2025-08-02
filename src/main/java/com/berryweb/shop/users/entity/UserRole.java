package com.berryweb.shop.users.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserRole {

    USER("USER", "사용자", 1),
    SYSOP("SYSOP", "운영자", 2),
    ADMIN("ADMIN", "관리자", 3);

    private final String code;
    private final String displayName;
    private final int level;

    // 권한 레벨 비교
    public boolean isHigherThan(UserRole other) {
        return this.level > other.level;
    }

    public boolean isHigherOrEqualTo(UserRole other) {
        return this.level >= other.level;
    }

    public boolean isLowerThan(UserRole other) {
        return this.level < other.level;
    }

    // 권한 체크 메서드들
    public boolean canManagePosts() {
        return this == SYSOP || this == ADMIN;
    }

    public boolean canManageUsers() {
        return this == ADMIN;
    }

    public boolean canManageComments() {
        return this == SYSOP || this == ADMIN;
    }

    public boolean canManageFiles() {
        return this == SYSOP || this == ADMIN;
    }

    public boolean canAccessAdminPanel() {
        return this == ADMIN;
    }

    public boolean canModerateContent() {
        return this == SYSOP || this == ADMIN;
    }

    // 문자열로부터 UserRole 찾기
    public static UserRole fromString(String role) {
        if (role == null) {
            return USER;
        }

        try {
            return valueOf(role.toUpperCase());
        } catch (IllegalArgumentException e) {
            return USER;
        }
    }

    // 코드로부터 UserRole 찾기
    public static UserRole fromCode(String code) {
        if (code == null) {
            return USER;
        }

        for (UserRole role : values()) {
            if (role.code.equals(code)) {
                return role;
            }
        }
        return USER;
    }

    // 모든 역할 정보를 문자열로 반환
    public static String getAllRolesInfo() {
        StringBuilder sb = new StringBuilder();
        for (UserRole role : values()) {
            sb.append(role.name())
                    .append(" (")
                    .append(role.displayName)
                    .append(", Level: ")
                    .append(role.level)
                    .append("), ");
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return displayName;
    }

}
