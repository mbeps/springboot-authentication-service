package com.maruf.auth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

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
 * The MongoDB TTL
 * index on {@code expiresAt} automatically removes expired tokens from the
 * database.
 *
 * <p>
 * Database collection: {@code refresh_tokens}
 * Unique constraint on token ensures one active token per session.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.RefreshTokenStore for token lifecycle management
 * @see com.maruf.auth.controller.AuthController for refresh endpoint
 */
@Document(collection = "refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

	/**
	 * MongoDB document ID (ObjectId).
	 * Auto-generated on document creation.
	 */
	@Id
	private String id;

	/**
	 * The refresh token value (SHA-256 hash if hashing is enabled).
	 * Unique constraint enforced at database level to prevent duplicate active
	 * tokens.
	 * Raw token is generated as a secure random string; hash is stored for
	 * security.
	 */
	@Indexed(unique = true)
	private String token;

	/**
	 * The user's email address (login identifier).
	 * Indexed for efficient user-based queries (e.g., "find all tokens for user").
	 */
	@Indexed
	private String username;

	/**
	 * Token expiration timestamp (7 days from creation by default).
	 * MongoDB TTL index automatically deletes this document when this instant is
	 * reached.
	 * Field name and TTL behavior configured via Spring Data MongoDB annotations.
	 */
	@Indexed(expireAfter = "0s")
	private Instant expiresAt;

	/**
	 * Timestamp when this token was originally created.
	 * Used for audit trailing and understanding token age.
	 */
	private Instant createdAt;

	/**
	 * Timestamp of the last refresh request using this token.
	 * Updated on each call to {@code /api/auth/refresh}.
	 * Useful for tracking active sessions and detecting stale tokens.
	 */
	private Instant lastUsed;
}
