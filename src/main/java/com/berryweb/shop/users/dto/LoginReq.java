package com.berryweb.shop.users.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginReq {

    @NotBlank(message = "사용자명 또는 이메일은 필수입니다")
    private String usernameOrEmail;

    @NotBlank(message = "비밀번호는 필수입니다")
    private String password;

    private Boolean rememberMe = false;

}
