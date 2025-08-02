package com.berryweb.shop.users.service;

import com.berryweb.shop.users.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;

    private static final String TOKEN_TYPE = "Bearer";

    // 토큰에서 사용자명 추출
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // 토큰에서 만료일 추출
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // 토큰에서 사용자 ID 추출
    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }

    // 토큰에서 사용자 역할 추출
    public String extractUserRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    // 토큰에서 특정 클레임 추출
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 액세스 토큰 생성
    public String generateAccessToken(User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId());
        extraClaims.put("role", user.getRole().name());
        extraClaims.put("email", user.getEmail());
        extraClaims.put("fullName", user.getFullName());
        extraClaims.put("tokenType", "access");

        return generateToken(extraClaims, user, jwtExpiration);
    }

    // 리프레시 토큰 생성
    public String generateRefreshToken(User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId());
        extraClaims.put("tokenType", "refresh");

        return generateToken(extraClaims, user, refreshExpiration);
    }

    // 토큰 생성
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, Long expiration) {
        return buildToken(extraClaims, userDetails, expiration);
    }

    // 토큰 빌드
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, Long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSignInKey())
                .compact();
    }

    // 토큰 유효성 검사
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    // 토큰 만료 확인
    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            log.error("Token expiration check failed: {}", e.getMessage());
            return true;
        }
    }

    // 토큰 타입 확인 (access/refresh)
    public boolean isRefreshToken(String token) {
        try {
            String tokenType = extractClaim(token, claims -> claims.get("tokenType", String.class));
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isAccessToken(String token) {
        try {
            String tokenType = extractClaim(token, claims -> claims.get("tokenType", String.class));
            return "access".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰에서 모든 클레임 추출
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
            throw new RuntimeException("JWT token is expired", e);
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
            throw new RuntimeException("JWT token is unsupported", e);
        } catch (MalformedJwtException e) {
            log.error("JWT token is malformed: {}", e.getMessage());
            throw new RuntimeException("JWT token is malformed", e);
        } catch (SecurityException e) {
            log.error("JWT signature validation failed: {}", e.getMessage());
            throw new RuntimeException("JWT signature validation failed", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT token compact of handler are invalid: {}", e.getMessage());
            throw new RuntimeException("JWT token compact of handler are invalid", e);
        }
    }

    // 서명 키 생성
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 토큰 만료까지 남은 시간 (밀리초)
    public long getTokenExpirationTime(String token) {
        Date expiration = extractExpiration(token);
        return expiration.getTime() - new Date().getTime();
    }

    // 토큰 만료까지 남은 시간 (초)
    public long getTokenExpirationTimeInSeconds(String token) {
        return getTokenExpirationTime(token) / 1000;
    }

    // 토큰에서 Bearer 접두어 제거
    public String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    // 토큰 정보 로깅 (디버깅용)
    public void logTokenInfo(String token) {
        try {
            Claims claims = extractAllClaims(token);
            log.debug("Token Info - Subject: {}, Issued: {}, Expires: {}, Role: {}",
                    claims.getSubject(),
                    claims.getIssuedAt(),
                    claims.getExpiration(),
                    claims.get("role"));
        } catch (Exception e) {
            log.error("Failed to extract token info: {}", e.getMessage());
        }
    }

    // 토큰 갱신 가능 여부 확인 (만료 1시간 전부터 갱신 가능)
    public boolean canRefreshToken(String token) {
        try {
            Date expiration = extractExpiration(token);
            Date now = new Date();
            long timeUntilExpiration = expiration.getTime() - now.getTime();
            long oneHourInMillis = 60 * 60 * 1000;

            return timeUntilExpiration <= oneHourInMillis && timeUntilExpiration > 0;
        } catch (Exception e) {
            return false;
        }
    }

    // JWT 설정 정보 반환
    public Map<String, Object> getJwtConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("accessTokenExpiration", jwtExpiration);
        config.put("refreshTokenExpiration", refreshExpiration);
        config.put("tokenType", TOKEN_TYPE);
        return config;
    }

}
