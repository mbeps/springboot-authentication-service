package com.maruf.auth.repository;

import com.maruf.auth.entity.InvalidatedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA repository for InvalidatedToken entity (access token blacklist).
 *
 * <p>
 * Extends {@code JpaRepository} to provide CRUD operations and blacklist
 * verification
 * for InvalidatedToken entities in the "invalidated_access_tokens" table.
 */
@Repository
public interface InvalidatedTokenRepository extends JpaRepository<InvalidatedToken, UUID> {
	/**
	 * Checks if a given access token has been invalidated (revoked).
	 *
	 * @param token The access token (JWT string) to check
	 * @return {@code true} if the token is in the blacklist; {@code false} if it's
	 *         valid or already expired
	 */
	boolean existsByToken(String token);

	/**
	 * Deletes all invalidated tokens that have naturally expired.
	 *
	 * @param now The current timestamp
	 */
	void deleteByExpiresAtBefore(Instant now);
}
