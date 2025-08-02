package com.berryweb.shop.users.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserUpdateReq {

    @Email(message = "올바른 이메일 형식이 아닙니다")
    private String email;

    @Size(min = 1, max = 100, message = "이름은 1-100자 사이여야 합니다")
    private String fullName;

    @Size(max = 500, message = "소개는 500자를 초과할 수 없습니다")
    private String bio;

    @Size(max = 20, message = "전화번호는 20자를 초과할 수 없습니다")
    private String phone;

    @Size(max = 500, message = "아바타 URL은 500자를 초과할 수 없습니다")
    private String avatarUrl;

}
