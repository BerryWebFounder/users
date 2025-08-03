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
        if (role == null || role.trim().isEmpty()) {
            return USER;
        }

        String normalizedRole = role.trim().toUpperCase();

        try {
            return valueOf(normalizedRole);
        } catch (IllegalArgumentException e) {
            return USER;
        }
    }

    // 코드로부터 UserRole 찾기
    public static UserRole fromCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return USER;
        }

        for (UserRole role : values()) {
            if (role.code.equalsIgnoreCase(code.trim())) {
                return role;
            }
        }
        return USER;
    }

    // 디스플레이 이름으로부터 UserRole 찾기
    public static UserRole fromDisplayName(String displayName) {
        if (displayName == null || displayName.trim().isEmpty()) {
            return USER;
        }

        for (UserRole role : values()) {
            if (role.displayName.equals(displayName.trim())) {
                return role;
            }
        }
        return USER;
    }

    // 레벨로부터 UserRole 찾기
    public static UserRole fromLevel(int level) {
        for (UserRole role : values()) {
            if (role.level == level) {
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
                    .append(")");

            if (role != ADMIN) { // 마지막이 아니면 쉼표 추가
                sb.append(", ");
            }
        }
        return sb.toString();
    }

    // 특정 레벨 이상의 역할들 반환
    public static UserRole[] getRolesAboveLevel(int minLevel) {
        return java.util.Arrays.stream(values())
                .filter(role -> role.level >= minLevel)
                .toArray(UserRole[]::new);
    }

    // 특정 레벨 이하의 역할들 반환
    public static UserRole[] getRolesBelowLevel(int maxLevel) {
        return java.util.Arrays.stream(values())
                .filter(role -> role.level <= maxLevel)
                .toArray(UserRole[]::new);
    }

    // 관리 권한이 있는 역할들 반환
    public static UserRole[] getManagementRoles() {
        return java.util.Arrays.stream(values())
                .filter(role -> role.canManagePosts() || role.canManageUsers())
                .toArray(UserRole[]::new);
    }

    // 역할의 권한 설명 반환
    public String getPermissionDescription() {
        return switch (this) {
            case USER -> "기본 사용자 권한 (글 작성, 댓글 작성)";
            case SYSOP -> "운영자 권한 (게시글 관리, 댓글 관리, 파일 관리)";
            case ADMIN -> "관리자 권한 (모든 권한, 사용자 관리, 시스템 관리)";
        };
    }

    // 다음 단계 역할 반환
    public UserRole getNextRole() {
        return switch (this) {
            case USER -> SYSOP;
            case SYSOP -> ADMIN;
            case ADMIN -> ADMIN; // 최고 권한
        };
    }

    // 이전 단계 역할 반환
    public UserRole getPreviousRole() {
        return switch (this) {
            case ADMIN -> SYSOP;
            case SYSOP -> USER;
            case USER -> USER; // 최하 권한
        };
    }

    @Override
    public String toString() {
        return displayName;
    }

}