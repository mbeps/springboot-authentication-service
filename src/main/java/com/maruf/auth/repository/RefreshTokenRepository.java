package com.maruf.auth.repository;

import com.maruf.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * JPA repository for RefreshToken entity.
 *
 * <p>
 * Extends {@code JpaRepository} to provide CRUD operations and custom query
 * methods
 * for managing RefreshToken entities in the "refresh_tokens" table.
 *
 * <p>
 * Handles token lifecycle: storage on login/signup, lookup on refresh, deletion
 * on logout
 * or token rotation.
 *
 * <p>
 * Tokens are stored as SHA-256 hashes (configurable via
 * {@code app.security.refresh-token.hashing-enabled})
 * for added security; plaintext comparison happens at the service layer.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.entity.RefreshToken for entity structure
 * @see com.maruf.auth.service.RefreshTokenStore for storage/retrieval logic
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
	/**
	 * Finds a refresh token entity by its token value (SHA-256 hash).
	 *
	 * <p>
	 * Used during token refresh to validate and retrieve the token from the
	 * database.
	 * If the database uses hashing, the input {@code token} should already be
	 * hashed (done by caller).
	 *
	 * @param token The refresh token (or its hash) to search for
	 * @return {@code Optional.of(refreshToken)} if found; {@code Optional.empty()}
	 *         if not found or expired
	 */
	Optional<RefreshToken> findByToken(String token);

	/**
	 * Deletes a refresh token entity by its token value.
	 *
	 * <p>
	 * Used during token rotation (when
	 * {@code app.security.refresh-token.rotation-enabled=true})
	 * to invalidate the old token after issuing a new one. Also called on explicit
	 * logout
	 * to prevent token reuse.
	 *
	 * @param token The refresh token (or its hash) to delete
	 */
	void deleteByToken(String token);

	/**
	 * Deletes all refresh tokens that have expired.
	 *
	 * @param now The current timestamp
	 */
	void deleteByExpiresAtBefore(Instant now);
}
