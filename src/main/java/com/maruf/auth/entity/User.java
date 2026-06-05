package com.maruf.auth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

/**
 * Represents a local user account with email/password credentials.
 *
 * <p>
 * This entity stores user profile information and credentials for local
 * (email/password) authentication.
 * Users created via OAuth2 flows (GitHub, Microsoft Entra ID) are typically not
 * persisted in this collection
 * unless explicitly registered via the local auth signup endpoint.
 *
 * <p>
 * Database collection: {@code users}
 * Unique constraint on email ensures one user per email address.
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.LocalAuthService for credential management
 * @see com.maruf.auth.dto.SignupRequest for user creation request contract
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "users")
public class User {
	/**
	 * MongoDB document ID (ObjectId).
	 * Auto-generated on document creation.
	 */
	@Id
	private String id;

	/**
	 * User email address; serves as the login identifier.
	 * Unique constraint enforced at database level.
	 * Must match Jakarta @Email validation pattern on signup.
	 */
	@Indexed(unique = true)
	private String email;

	/**
	 * BCrypt-hashed password digest.
	 * Never stored in plaintext; verified via BCrypt comparison during login.
	 */
	private String password;

	/**
	 * User's display name.
	 * Non-empty string required on signup.
	 */
	private String name;

	/**
	 * Optional Profile picture URL.
	 * May be null for users without a profile image.
	 */
	private String avatarUrl;

	/**
	 * List of granted authority roles (e.g., "ROLE_USER").
	 * Used by Spring Security for access control via @PreAuthorize.
	 */
	private List<String> roles;
}
