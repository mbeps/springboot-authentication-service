package com.maruf.auth.repository;

import com.maruf.auth.entity.InvalidatedToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

/**
 * MongoDB repository for InvalidatedToken entity (access token blacklist).
 *
 * <p>
 * Extends {@code MongoRepository} to provide CRUD operations and blacklist
 * verification
 * for InvalidatedToken documents in the "invalidated_access_tokens" collection.
 *
 * <p>
 * When a user logs out, their current access token is added to this blacklist
 * to prevent
 * token replay attacks until natural expiration. The MongoDB TTL index on
 * {@code expiresAt}
 * automatically removes entries when the token expires (typically 15 minutes
 * after logout).
 *
 * <p>
 * This repository is used exclusively by the authentication service; stateless resource servers
 * typically rely on JWT expiration for validation and do not check this dynamic blacklist.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.entity.InvalidatedToken for entity structure
 * @see com.maruf.auth.service.RefreshTokenStore for blacklist operations
 * @see com.maruf.auth.config.JwtAuthenticationFilter for blacklist checks
 */
@Repository
public interface InvalidatedTokenRepository extends MongoRepository<InvalidatedToken, String> {
	/**
	 * Checks if a given access token has been invalidated (revoked).
	 *
	 * <p>
	 * Called by {@code JwtAuthenticationFilter} on every request to verify the
	 * token
	 * has not been blacklisted via logout. This is a defensive measure against
	 * token
	 * replay: even if an attacker obtains a token, it cannot be used after the
	 * legitimate
	 * user logs out.
	 *
	 * @param token The access token (JWT string) to check
	 * @return {@code true} if the token is in the blacklist; {@code false} if it's
	 *         valid or already expired
	 */
	boolean existsByToken(String token);
}
