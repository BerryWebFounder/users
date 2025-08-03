package com.berryweb.shop.users.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

@Configuration
@Slf4j
public class WebConfig implements WebMvcConfigurer {

    // ============ CORS 설정 ============

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOriginPatterns(
                        "http://localhost:3000",    // Nuxt 개발 서버
                        "http://localhost:8080",    // API Gateway
                        "https://*.berryweb.co.kr"  // 운영 도메인
                )
                .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }

    // ============ 정적 리소스 설정 ============

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // 정적 리소스 경로 설정
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/")
                .setCachePeriod(31556926); // 1년

        registry.addResourceHandler("/uploads/**")
                .addResourceLocations("file:uploads/")
                .setCachePeriod(604800); // 1주일
    }

    // ============ 인터셉터 설정 ============

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 로케일 변경 인터셉터
        registry.addInterceptor(localeChangeInterceptor());

        // 로깅 인터셉터
        registry.addInterceptor(new LoggingInterceptor())
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/health", "/actuator/**");

        // 성능 모니터링 인터셉터
        registry.addInterceptor(new PerformanceInterceptor())
                .addPathPatterns("/api/**");

        // API 버전 인터셉터
        registry.addInterceptor(apiVersionInterceptor())
                .addPathPatterns("/api/**");
    }

    // ============ 메시지 컨버터 설정 ============

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new MappingJackson2HttpMessageConverter(objectMapper()));
    }

    // ============ Jackson ObjectMapper 설정 ============

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        // Java 8 시간 모듈 등록
        mapper.registerModule(new JavaTimeModule());

        // null 값 제외
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        // 프로퍼티 명명 전략 (camelCase)
        mapper.setPropertyNamingStrategy(PropertyNamingStrategies.LOWER_CAMEL_CASE);

        // 알 수 없는 프로퍼티 무시
        mapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        // 빈 객체 직렬화 실패 방지
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

        return mapper;
    }

    // ============ 국제화 설정 ============

    @Bean
    public SessionLocaleResolver localeResolver() {
        SessionLocaleResolver resolver = new SessionLocaleResolver();
        resolver.setDefaultLocale(Locale.KOREAN);
        return resolver;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
        interceptor.setParamName("lang");
        return interceptor;
    }

    // ============ 사용자 정의 인터셉터들 ============

    /**
     * 요청/응답 로깅 인터셉터
     */
    public static class LoggingInterceptor implements HandlerInterceptor {

        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
            if (log.isDebugEnabled()) {
                String clientIp = getClientIpAddress(request);
                log.debug("Request: {} {} from {} - User-Agent: {}",
                        request.getMethod(),
                        request.getRequestURI(),
                        clientIp,
                        request.getHeader("User-Agent"));
            }

            // 요청 시작 시간 저장
            request.setAttribute("startTime", System.currentTimeMillis());

            return true;
        }

        @Override
        public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                    Object handler, Exception ex) {

            Long startTime = (Long) request.getAttribute("startTime");
            if (startTime != null) {
                long duration = System.currentTimeMillis() - startTime;

                if (log.isDebugEnabled()) {
                    log.debug("Response: {} {} - Status: {} - Duration: {}ms",
                            request.getMethod(),
                            request.getRequestURI(),
                            response.getStatus(),
                            duration);
                }

                // 느린 요청 경고 (5초 이상)
                if (duration > 5000) {
                    log.warn("Slow request detected: {} {} - Duration: {}ms",
                            request.getMethod(), request.getRequestURI(), duration);
                }

                // 매우 느린 요청 에러 (30초 이상)
                if (duration > 30000) {
                    log.error("Very slow request detected: {} {} - Duration: {}ms",
                            request.getMethod(), request.getRequestURI(), duration);
                }
            }

            if (ex != null) {
                log.error("Request failed: {} {} - Error: {}",
                        request.getMethod(), request.getRequestURI(), ex.getMessage());
            }
        }

        private String getClientIpAddress(HttpServletRequest request) {
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
                return xForwardedFor.split(",")[0].trim();
            }

            String xRealIP = request.getHeader("X-Real-IP");
            if (xRealIP != null && !xRealIP.isEmpty() && !"unknown".equalsIgnoreCase(xRealIP)) {
                return xRealIP;
            }

            return request.getRemoteAddr();
        }
    }

    /**
     * 성능 모니터링 인터셉터
     */
    public static class PerformanceInterceptor implements HandlerInterceptor {

        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
            request.setAttribute("perfStartTime", System.nanoTime());
            return true;
        }

        @Override
        public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                    Object handler, Exception ex) {

            Long startTime = (Long) request.getAttribute("perfStartTime");
            if (startTime != null) {
                long duration = System.nanoTime() - startTime;
                double durationMs = duration / 1_000_000.0;

                // 성능 헤더 추가
                response.setHeader("X-Response-Time", String.format("%.2fms", durationMs));

                // 매우 느린 요청 로깅 (10초 이상)
                if (durationMs > 10000) {
                    log.error("Very slow request: {} {} - Duration: {:.2f}ms",
                            request.getMethod(), request.getRequestURI(), durationMs);
                }

                // 성능 메트릭 수집 (추후 Micrometer 연동)
                // meterRegistry.timer("http.request.duration", "method", request.getMethod(), "status", String.valueOf(response.getStatus()))
                //     .record(Duration.ofNanos(duration));
            }
        }
    }

    /**
     * API 버전 관리를 위한 헤더 설정
     */
    @Bean
    public HandlerInterceptor apiVersionInterceptor() {
        return new HandlerInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
                // API 버전 헤더 추가
                response.setHeader("X-API-Version", "1.0");
                response.setHeader("X-Service-Name", "users-service");
                response.setHeader("X-Server-Time", LocalDateTime.now().toString());

                // CORS 헤더 추가 (필요시)
                if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
                    response.setStatus(HttpServletResponse.SC_OK);
                    return false;
                }

                return true;
            }
        };
    }

    /**
     * 보안 헤더 설정 인터셉터
     */
    @Bean
    public HandlerInterceptor securityHeaderInterceptor() {
        return new HandlerInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
                // 보안 헤더 설정
                response.setHeader("X-Content-Type-Options", "nosniff");
                response.setHeader("X-Frame-Options", "DENY");
                response.setHeader("X-XSS-Protection", "1; mode=block");
                response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

                return true;
            }
        };
    }

    // ============ 추가 Bean 설정들 ============

    /**
     * 요청 본문 크기 제한 설정은 application.yml에서 처리
     * spring.servlet.multipart.max-file-size=10MB
     * spring.servlet.multipart.max-request-size=10MB
     * server.max-http-header-size=8KB
     */

}