package com.maruf.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a long-lived refresh token used for automatic JWT re-issuance.
 *
 * <p>
 * Refresh tokens are stored with optional SHA-256 hashing (configurable via
 * {@code app.security.refresh-token.hashing-enabled}). Each token is associated
 * with a user
 * and has an expiration time of 7 days by default
 * ({@code jwt.refresh-token-expiration}).
 *
 * <p>
 * Supports token rotation: when enabled
 * ({@code app.security.refresh-token.rotation-enabled}),
 * each use of a refresh token invalidates the old token and issues a new one.
 * The {@code TokenCleanupService}
 * automatically removes expired tokens from the database.
 *
 * <p>
 * Database table: {@code refresh_tokens}
 * Unique constraint on token ensures one active token per session.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.RefreshTokenStore for token lifecycle management
 * @see com.maruf.auth.controller.AuthController for refresh endpoint
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
		@Index(name = "idx_refresh_token_username", columnList = "username"),
		@Index(name = "idx_refresh_token_expires_at", columnList = "expiresAt")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

	/**
	 * Primary key (UUID).
	 * Auto-generated on insertion.
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;

	/**
	 * The refresh token value (SHA-256 hash if hashing is enabled).
	 * Unique constraint enforced at database level to prevent duplicate active
	 * tokens.
	 * Raw token is generated as a secure random string; hash is stored for
	 * security.
	 */
	@Column(unique = true, nullable = false)
	private String token;

	/**
	 * The user's email address (login identifier).
	 * Indexed for efficient user-based queries (e.g., "find all tokens for user").
	 */
	@Column(nullable = false)
	private String username;

	/**
	 * Token expiration timestamp (7 days from creation by default).
	 * Indexed for efficient cleanup.
	 */
	@Column(nullable = false)
	private Instant expiresAt;

	/**
	 * Timestamp when this token was originally created.
	 * Used for audit trailing and understanding token age.
	 */
	@Column(nullable = false)
	private Instant createdAt;

	/**
	 * Timestamp of the last refresh request using this token.
	 * Updated on each call to {@code /api/auth/refresh}.
	 * Useful for tracking active sessions and detecting stale tokens.
	 */
	@Column(nullable = false)
	private Instant lastUsed;
}
