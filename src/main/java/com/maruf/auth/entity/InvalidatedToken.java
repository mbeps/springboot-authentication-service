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
 * Represents a revoked (invalidated) JWT access token temporarily stored in a
 * blacklist.
 *
 * <p>
 * When a user logs out, their current access token is added to this blacklist
 * to prevent its
 * further use even if a malicious actor obtains it before natural expiration.
 * This is a defensive
 * measure against token replay attacks. The token remains in the blacklist only
 * until its natural
 * expiration time, at which point it becomes cryptographically invalid anyway.
 *
 * <p>
 * Database collection: {@code invalidated_access_tokens}
 * The MongoDB TTL index on {@code expiresAt} automatically removes entries when
 * the token expires.
 * This document is typically only checked by the authentication service; stateless resource servers
 * normally rely on JWT expiration for validation.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.RefreshTokenStore for blacklist operations
 * @see com.maruf.auth.config.JwtAuthenticationFilter for blacklist verification
 */
@Document(collection = "invalidated_access_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InvalidatedToken {
	/**
	 * MongoDB document ID (ObjectId).
	 * Auto-generated on document creation.
	 */
	@Id
	private String id;

	/**
	 * The raw JWT access token string being invalidated.
	 * Unique constraint enforced to prevent duplicate entries.
	 * Checked against every incoming request in {@code JwtAuthenticationFilter}.
	 */
	@Indexed(unique = true)
	private String token;

	/**
	 * The email/login of the user who logged out.
	 * Used for audit logging and identifying which user's tokens were revoked.
	 */
	private String username;

	/**
	 * Token's natural expiration time (matching the {@code exp} claim in the JWT).
	 * MongoDB TTL index automatically deletes this entry when timestamp is reached.
	 * Typically 15 minutes from logout; no need to keep record longer than JWT
	 * validity.
	 */
	@Indexed(expireAfter = "0s")
	private Instant expiresAt;

	/**
	 * Timestamp when the token was invalidated (logout instant).
	 * Used for audit trails to understand when the revocation occurred.
	 */
	private Instant invalidatedAt;

	/**
	 * Reason code for invalidation (e.g., "logout", "token_revocation").
	 * Currently always set to "logout" but allows for future extensibility
	 * (e.g., "suspicious_activity", "password_change").
	 */
	private String reason;
}
