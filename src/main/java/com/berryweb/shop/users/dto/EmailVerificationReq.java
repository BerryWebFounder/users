package com.berryweb.shop.users.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class EmailVerificationReq {

    @NotBlank(message = "인증 토큰은 필수입니다")
    private String token;

}
