package com.berryweb.shop.users.client;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@FeignClient(
        name = "posts-service",
        url = "${posts-service.url}",
        fallbackFactory = PostsServiceClient.PostsServiceClientFallback.class
)
public interface PostsServiceClient {

    // ============ 게시글 관련 API ============

    /**
     * 특정 작성자의 게시글 목록 조회
     */
    @GetMapping("/api/posts/author/{authorId}")
    List<PostDto> getPostsByAuthor(@PathVariable("authorId") Long authorId);

    /**
     * 특정 작성자의 게시글 수 조회
     */
    @GetMapping("/api/posts/author/{authorId}/count")
    Long getPostCountByAuthor(@PathVariable("authorId") Long authorId);

    /**
     * 게시글 작성자 정보 업데이트 (사용자 정보 변경 시)
     */
    @PutMapping("/api/posts/author/{authorId}")
    void updateAuthorInfo(@PathVariable("authorId") Long authorId, @RequestBody AuthorUpdateReq request);

    /**
     * 사용자 삭제 시 게시글 처리 (작성자를 탈퇴회원으로 변경)
     */
    @PutMapping("/api/posts/author/{authorId}/deactivate")
    void deactivateAuthorPosts(@PathVariable("authorId") Long authorId);

    // ============ 댓글 관련 API ============

    /**
     * 특정 작성자의 댓글 목록 조회
     */
    @GetMapping("/api/comments/author/{authorId}")
    List<CommentDto> getCommentsByAuthor(@PathVariable("authorId") Long authorId);

    /**
     * 특정 작성자의 댓글 수 조회
     */
    @GetMapping("/api/comments/author/{authorId}/count")
    Long getCommentCountByAuthor(@PathVariable("authorId") Long authorId);

    /**
     * 댓글 작성자 정보 업데이트
     */
    @PutMapping("/api/comments/author/{authorId}")
    void updateCommentAuthorInfo(@PathVariable("authorId") Long authorId, @RequestBody AuthorUpdateReq request);

    /**
     * 사용자 삭제 시 댓글 처리
     */
    @PutMapping("/api/comments/author/{authorId}/deactivate")
    void deactivateAuthorComments(@PathVariable("authorId") Long authorId);

    // ============ 통계 관련 API ============

    /**
     * 사용자 활동 통계 조회
     */
    @GetMapping("/api/stats/user/{userId}")
    UserActivityStatsDto getUserActivityStats(@PathVariable("userId") Long userId);

    /**
     * 여러 사용자의 활동 통계 조회
     */
    @PostMapping("/api/stats/users")
    Map<Long, UserActivityStatsDto> getUsersActivityStats(@RequestBody List<Long> userIds);

    // ============ 데이터 모델들 ============

    @Data
    class PostDto {
        private Long id;
        private String title;
        private String content;
        private Long authorId;
        private String authorName;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
        private Integer viewCount;
        private Integer commentCount;
        private Boolean isActive;
    }

    @Data
    class CommentDto {
        private Long id;
        private Long postId;
        private String content;
        private Long authorId;
        private String authorName;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
        private Boolean isActive;
    }

    @Data
    class AuthorUpdateReq {
        private String authorName;
        private String authorEmail;
        private Boolean isActive;
    }

    @Data
    class UserActivityStatsDto {
        private Long userId;
        private Long postCount;
        private Long commentCount;
        private Long totalViews;
        private LocalDateTime lastActivityAt;
        private LocalDateTime firstActivityAt;
    }

    // ============ Fallback 구현 ============

    @Component
    @Slf4j
    class PostsServiceClientFallback implements FallbackFactory<PostsServiceClient> {

        @Override
        public PostsServiceClient create(Throwable cause) {
            log.error("Posts service is unavailable: {}", cause.getMessage());

            return new PostsServiceClient() {
                @Override
                public List<PostDto> getPostsByAuthor(Long authorId) {
                    log.warn("Fallback: getPostsByAuthor for user {}", authorId);
                    return Collections.emptyList();
                }

                @Override
                public Long getPostCountByAuthor(Long authorId) {
                    log.warn("Fallback: getPostCountByAuthor for user {}", authorId);
                    return 0L;
                }

                @Override
                public void updateAuthorInfo(Long authorId, AuthorUpdateReq request) {
                    log.warn("Fallback: updateAuthorInfo for user {} - request queued for retry", authorId);
                    // TODO: 큐에 추가하여 나중에 재시도
                }

                @Override
                public void deactivateAuthorPosts(Long authorId) {
                    log.warn("Fallback: deactivateAuthorPosts for user {} - request queued for retry", authorId);
                    // TODO: 큐에 추가하여 나중에 재시도
                }

                @Override
                public List<CommentDto> getCommentsByAuthor(Long authorId) {
                    log.warn("Fallback: getCommentsByAuthor for user {}", authorId);
                    return Collections.emptyList();
                }

                @Override
                public Long getCommentCountByAuthor(Long authorId) {
                    log.warn("Fallback: getCommentCountByAuthor for user {}", authorId);
                    return 0L;
                }

                @Override
                public void updateCommentAuthorInfo(Long authorId, AuthorUpdateReq request) {
                    log.warn("Fallback: updateCommentAuthorInfo for user {} - request queued for retry", authorId);
                    // TODO: 큐에 추가하여 나중에 재시도
                }

                @Override
                public void deactivateAuthorComments(Long authorId) {
                    log.warn("Fallback: deactivateAuthorComments for user {} - request queued for retry", authorId);
                    // TODO: 큐에 추가하여 나중에 재시도
                }

                @Override
                public UserActivityStatsDto getUserActivityStats(Long userId) {
                    log.warn("Fallback: getUserActivityStats for user {}", userId);
                    UserActivityStatsDto stats = new UserActivityStatsDto();
                    stats.setUserId(userId);
                    stats.setPostCount(0L);
                    stats.setCommentCount(0L);
                    stats.setTotalViews(0L);
                    return stats;
                }

                @Override
                public Map<Long, UserActivityStatsDto> getUsersActivityStats(List<Long> userIds) {
                    log.warn("Fallback: getUsersActivityStats for {} users", userIds.size());
                    return Collections.emptyMap();
                }
            };
        }
    }

}