package com.maruf.auth.service;

import com.maruf.auth.repository.InvalidatedTokenRepository;
import com.maruf.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Background service for cleaning up expired tokens from PostgreSQL.
 *
 * <p>
 * Replaces PostgreSQL's built-in TTL (Time-To-Live) index functionality.
 * Runs periodically to remove tokens that have reached their natural expiration time.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final InvalidatedTokenRepository invalidatedTokenRepository;

    /**
     * Deletes expired refresh tokens and invalidated access tokens.
     * Runs every hour at the top of the hour.
     */
    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        log.info("Starting scheduled cleanup of expired tokens at {}", now);

        try {
            refreshTokenRepository.deleteByExpiresAtBefore(now);
            log.debug("Expired refresh tokens cleaned up");

            invalidatedTokenRepository.deleteByExpiresAtBefore(now);
            log.debug("Expired invalidated access tokens cleaned up");

            log.info("Token cleanup completed successfully");
        } catch (Exception e) {
            log.error("Error occurred during token cleanup: {}", e.getMessage(), e);
        }
    }
}
