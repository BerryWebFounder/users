package com.berryweb.shop.users.dto;

import com.berryweb.shop.users.entity.UserRole;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UserRoleUpdateReq {

    @NotNull(message = "역할은 필수입니다")
    private UserRole role;

    private String reason; // 변경 사유 (로그용)

}
