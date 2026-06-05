package com.maruf.auth.service;

import com.maruf.auth.entity.InvalidatedToken;
import com.maruf.auth.entity.RefreshToken;
import com.maruf.auth.repository.InvalidatedTokenRepository;
import com.maruf.auth.repository.RefreshTokenRepository;
import com.maruf.auth.config.RefreshTokenSecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

/**
 * Service for managing the complete lifecycle of refresh tokens and access
 * token blacklist.
 *
 * <p>
 * Provides a secure, MongoDB-backed token storage layer with support for:
 * <ul>
 * <li><strong>Token persistence:</strong> Stores refresh tokens with creation
 * and last-used timestamps</li>
 * <li><strong>Automatic rotation:</strong> Invalidates old tokens and stores
 * new ones on each refresh</li>
 * <li><strong>SHA-256 hashing:</strong> Optionally hashes refresh tokens before
 * storage to protect against database dumps</li>
 * <li><strong>Access token blacklist:</strong> Maintains a TTL-indexed
 * blacklist of revoked (logged out) access tokens</li>
 * <li><strong>TTL cleanup:</strong> MongoDB TTL indexes automatically delete
 * expired documents at expiration time</li>
 * </ul>
 *
 * <p>
 * <strong>Token hashing strategy:</strong> When
 * {@code app.security.refresh-token.hashing-enabled=true},
 * raw tokens are converted to SHA-256 Base64 URL-encoded hashes before storage.
 * This prevents an attacker
 * with database access from directly replaying stolen tokens. The application
 * stores only the hash,
 * with no reverse operation possible. On token lookup, the incoming token is
 * hashed identically and
 * compared against the stored hash.
 *
 * <p>
 * <strong>Refresh token rotation:</strong> When
 * {@code app.security.refresh-token.rotation-enabled=true},
 * each successful refresh invalidates the old token and issues a fresh one.
 * This reduces the window
 * for replay attacks if a token is compromised mid-session.
 *
 * <p>
 * <strong>Access token blacklist:</strong> When a user logs out, their access
 * token (still valid
 * for ~13 minutes) is stored in the {@code invalidated_access_tokens}
 * collection with its natural
 * expiration timestamp. The auth service filter checks this blacklist on every
 * request; resource servers
 * may not check the blacklist if they lack database access. MongoDB's TTL index
 * automatically removes
 * blacklisted tokens once their expiration time passes.
 *
 * @see RefreshToken entity for token storage structure
 * @see InvalidatedToken entity for blacklist storage structure
 * @see RefreshTokenSecurityProperties for hashing and rotation configuration
 * @author Maruf Bepary
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenStore {

	private final RefreshTokenRepository refreshTokenRepository;
	private final InvalidatedTokenRepository invalidatedTokenRepository;
	private final RefreshTokenSecurityProperties refreshTokenSecurityProperties;

	/**
	 * Persists a new refresh token to the database with expiration and usage
	 * metadata.
	 *
	 * <p>
	 * Applies optional SHA-256 hashing to the raw token before storage based on the
	 * {@code app.security.refresh-token.hashing-enabled} configuration. Stores
	 * creation
	 * and last-used timestamps to enable token rotation tracking and usage
	 * auditing.
	 * The MongoDB TTL index on the {@code expiresAt} field ensures automatic
	 * cleanup.
	 *
	 * @param token     the raw JWT refresh token string to persist
	 * @param username  the associated user's email or login identifier
	 * @param expiresAt the timestamp when this token becomes invalid; MongoDB TTL
	 *                  deletion occurs at this time
	 * @see #applyHash for hashing logic controlled by configuration
	 * @see RefreshToken entity for the storage structure
	 */
	public void storeRefreshToken(String token, String username, Instant expiresAt) {
		String tokenValue = applyHash(token);
		RefreshToken refreshToken = RefreshToken.builder()
				.token(tokenValue)
				.username(username)
				.expiresAt(expiresAt)
				.createdAt(Instant.now())
				.lastUsed(Instant.now())
				.build();

		refreshTokenRepository.save(refreshToken);
		log.debug("Stored refresh token for user: {}", username);
	}

	/**
	 * Retrieves the username associated with a given refresh token and updates its
	 * last-used timestamp.
	 *
	 * <p>
	 * Looks up the raw token by hashing it (if hashing is enabled) and performing a
	 * database
	 * query. If found, updates the {@code lastUsed} timestamp to the current
	 * instant before returning
	 * the username. Returns {@code null} if the token is not found or has expired
	 * (expired tokens
	 * are automatically deleted by MongoDB TTL index).
	 *
	 * @param token the raw JWT refresh token string
	 * @return the associated username (email/login), or {@code null} if token not
	 *         found or expired
	 * @see #applyHash for token hashing before lookup
	 * @see RefreshTokenRepository#findByToken for database query
	 */
	public String getUsernameFromRefreshToken(String token) {
		return findTokenRecord(token)
				.map(refreshToken -> {
					refreshToken.setLastUsed(Instant.now());
					refreshTokenRepository.save(refreshToken);
					return refreshToken.getUsername();
				})
				.orElse(null);
	}

	/**
	 * Removes a refresh token from the database, preventing future use.
	 *
	 * <p>
	 * Applies the same hashing logic as
	 * {@link #storeRefreshToken(String, String, Instant)}
	 * to locate and delete the token. Used during token rotation (when a new token
	 * is issued)
	 * and during logout (when the user explicitly invalidates their session).
	 *
	 * @param token the raw JWT refresh token string to invalidate
	 * @see RefreshTokenRepository#deleteByToken for database deletion
	 */
	public void invalidateRefreshToken(String token) {
		String hashedToken = applyHash(token);
		refreshTokenRepository.deleteByToken(hashedToken);
		log.debug("Refresh token invalidated");
	}

	/**
	 * Adds an access token to the blacklist, preventing its future use.
	 *
	 * <p>
	 * Called during logout to immediately revoke the current access token. The
	 * token is stored
	 * with its natural expiration time; MongoDB's TTL index automatically removes
	 * the blacklist
	 * entry once the token naturally expires (making the entry obsolete anyway).
	 * The raw token string
	 * is stored (not hashed) to allow quick blacklist checks during request
	 * processing.
	 *
	 * @param token     the raw JWT access token string to blacklist
	 * @param username  the associated username for audit trail and logging
	 * @param expiresAt the natural expiration time of the token; used for MongoDB
	 *                  TTL auto-cleanup
	 * @see InvalidatedTokenRepository#save for database persistence
	 * @see #isAccessTokenInvalidated for blacklist lookup during authentication
	 */
	public void invalidateAccessToken(String token, String username, Instant expiresAt) {
		InvalidatedToken invalidatedToken = InvalidatedToken.builder()
				.token(token)
				.username(username)
				.expiresAt(expiresAt)
				.invalidatedAt(Instant.now())
				.reason("logout")
				.build();

		invalidatedTokenRepository.save(invalidatedToken);
		log.debug("Access token invalidated");
	}

	/**
	 * Checks if an access token has been blacklisted (revoked).
	 *
	 * <p>
	 * Performs a database query to determine if the token exists in the blacklist.
	 * Called
	 * by {@link com.maruf.auth.config.JwtAuthenticationFilter} on every
	 * authenticated request
	 * to ensure that logged-out tokens are rejected even if they haven't naturally
	 * expired.
	 *
	 * @param token the raw JWT access token string to check
	 * @return true if the token is in the blacklist, false if it is valid/not
	 *         blacklisted
	 * @see InvalidatedTokenRepository#existsByToken for database lookup
	 * @see com.maruf.auth.config.JwtAuthenticationFilter#doFilterInternal
	 */
	public boolean isAccessTokenInvalidated(String token) {
		return invalidatedTokenRepository.existsByToken(token);
	}

	/**
	 * Applies optional SHA-256 hashing to a token based on configuration.
	 *
	 * <p>
	 * If {@code app.security.refresh-token.hashing-enabled=true}, converts the raw
	 * token
	 * to a SHA-256 hash and returns the Base64 URL-encoded result (without
	 * padding).
	 * If hashing is disabled, returns the token unchanged. This method is used
	 * consistently
	 * for both storage and lookup to ensure hashes match.
	 *
	 * @param token the raw token string
	 * @return the hashed token (if hashing enabled) or the original token (if
	 *         disabled)
	 * @throws IllegalStateException if SHA-256 algorithm is not available (should
	 *                               never occur)
	 * @see RefreshTokenSecurityProperties#isHashingEnabled
	 */
	private String applyHash(String token) {
		if (!refreshTokenSecurityProperties.isHashingEnabled()) {
			return token;
		}
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashed = digest.digest(token.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 digest is not available", e);
		}
	}

	/**
	 * Finds the refresh token record in the database using an optional hash lookup.
	 *
	 * <p>
	 * Applies the same hashing logic as {@link #applyHash(String)} before querying
	 * the database. Used internally by {@link #getUsernameFromRefreshToken(String)}
	 * and
	 * other token lifecycle operations. Returns empty Optional if the token is not
	 * found,
	 * which may indicate an invalid token, an already-rotated token, or an expired
	 * token
	 * (the latter of which may have been automatically deleted by MongoDB's TTL
	 * cleanup).
	 *
	 * @param token the raw refresh token string
	 * @return Optional containing the token record if found, or empty if not found
	 * @see RefreshTokenRepository#findByToken for database lookup
	 * @see #applyHash for hashing logic
	 */
	private Optional<RefreshToken> findTokenRecord(String token) {
		String hashedToken = applyHash(token);
		return refreshTokenRepository.findByToken(hashedToken);
	}
}
