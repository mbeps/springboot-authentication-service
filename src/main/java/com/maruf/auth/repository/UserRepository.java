package com.maruf.auth.repository;

import com.maruf.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * JPA repository for User entity (local auth users).
 *
 * <p>
 * Extends {@code JpaRepository} to provide CRUD operations and custom query
 * methods
 * for managing User entities in the "users" table.
 *
 * <p>
 * Used exclusively by {@code LocalAuthService} for credential-based
 * authentication
 * (email/password login and signup). Users authenticated via OAuth2 (GitHub,
 * Microsoft Entra ID)
 * are not stored in this repository unless explicitly registered via the signup
 * endpoint.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.entity.User for entity structure
 * @see com.maruf.auth.service.LocalAuthService for usage
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
	/**
	 * Finds a user by their email address.
	 *
	 * @param email The email to search (typically from login request)
	 * @return {@code Optional.of(user)} if a user with that email exists;
	 *         {@code Optional.empty()} otherwise
	 */
	Optional<User> findByEmail(String email);

	/**
	 * Checks if a user with the given email already exists in the database.
	 *
	 * @param email The email to check
	 * @return {@code true} if a user with this email exists (used to prevent
	 *         duplicate registration); {@code false} otherwise
	 */
	boolean existsByEmail(String email);
}
