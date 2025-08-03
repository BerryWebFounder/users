package com.berryweb.shop.users.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRes {

    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";

    /**
     * 액세스 토큰 만료 시간 (초 단위)
     * 예: 3600 = 1시간
     */
    private Long expiresIn;

    private UserRes user;

    public LoginRes(String accessToken, String refreshToken, Long expiresIn, UserRes user) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = "Bearer";
        this.expiresIn = expiresIn;
        this.user = user;
    }

    /**
     * 편의 메서드: 토큰이 만료되는 시간을 밀리초 단위로 반환
     */
    public Long getExpiresInMillis() {
        return expiresIn != null ? expiresIn * 1000 : null;
    }

    /**
     * 편의 메서드: 토큰이 만료되는 절대 시간을 반환 (현재 시간 + expiresIn)
     */
    public Long getExpiresAt() {
        return expiresIn != null ? System.currentTimeMillis() / 1000 + expiresIn : null;
    }

    /**
     * 편의 메서드: Authorization 헤더에 사용할 전체 토큰 문자열 반환
     */
    public String getAuthorizationHeader() {
        return tokenType + " " + accessToken;
    }

    /**
     * 편의 메서드: 토큰 응답 요약 정보 반환
     */
    public String getTokenSummary() {
        return String.format("AccessToken: %s..., RefreshToken: %s..., ExpiresIn: %ds",
                accessToken != null ? accessToken.substring(0, Math.min(20, accessToken.length())) : "null",
                refreshToken != null ? refreshToken.substring(0, Math.min(20, refreshToken.length())) : "null",
                expiresIn);
    }

}