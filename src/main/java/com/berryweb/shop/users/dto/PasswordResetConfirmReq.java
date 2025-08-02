package com.berryweb.shop.users.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PasswordResetConfirmReq {

    @NotBlank(message = "토큰은 필수입니다")
    private String token;

    @NotBlank(message = "새 비밀번호는 필수입니다")
    @Size(min = 8, message = "새 비밀번호는 최소 8자 이상이어야 합니다")
    private String newPassword;

    @NotBlank(message = "새 비밀번호 확인은 필수입니다")
    private String confirmNewPassword;

}
