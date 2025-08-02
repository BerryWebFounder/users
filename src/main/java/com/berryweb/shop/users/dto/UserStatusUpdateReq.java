package com.berryweb.shop.users.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UserStatusUpdateReq {

    @NotNull(message = "활성 상태는 필수입니다")
    private Boolean isActive;

    private String reason; // 변경 사유 (로그용)

}
