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
 * Database table: {@code invalidated_access_tokens}
 * The {@code TokenCleanupService} automatically removes entries when
 * the token expires.
 * This entity is typically only checked by the authentication service; stateless resource servers
 * normally rely on JWT expiration for validation.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.RefreshTokenStore for blacklist operations
 * @see com.maruf.auth.config.JwtAuthenticationFilter for blacklist verification
 */
@Entity
@Table(name = "invalidated_access_tokens", indexes = {
		@Index(name = "idx_invalidated_token_expires_at", columnList = "expiresAt")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InvalidatedToken {
	/**
	 * Primary key (UUID).
	 * Auto-generated on insertion.
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;

	/**
	 * The raw JWT access token string being invalidated.
	 * Unique constraint enforced to prevent duplicate entries.
	 * Checked against every incoming request in {@code JwtAuthenticationFilter}.
	 */
	@Column(unique = true, nullable = false, columnDefinition = "TEXT")
	private String token;

	/**
	 * The email/login of the user who logged out.
	 * Used for audit logging and identifying which user's tokens were revoked.
	 */
	@Column(nullable = false)
	private String username;

	/**
	 * Token's natural expiration time (matching the {@code exp} claim in the JWT).
	 * Indexed for efficient cleanup.
	 */
	@Column(nullable = false)
	private Instant expiresAt;

	/**
	 * Timestamp when the token was invalidated (logout instant).
	 * Used for audit trails to understand when the revocation occurred.
	 */
	@Column(nullable = false)
	private Instant invalidatedAt;

	/**
	 * Reason code for invalidation (e.g., "logout", "token_revocation").
	 * Currently always set to "logout" but allows for future extensibility
	 * (e.g., "suspicious_activity", "password_change").
	 */
	@Column(nullable = false)
	private String reason;
}
