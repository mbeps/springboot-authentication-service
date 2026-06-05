package com.maruf.auth.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * Represents a local user account with email/password credentials.
 *
 * <p>
 * This entity stores user profile information and credentials for local
 * (email/password) authentication.
 * Users created via OAuth2 flows (GitHub, Microsoft Entra ID) are typically not
 * persisted in this table
 * unless explicitly registered via the local auth signup endpoint.
 *
 * <p>
 * Database table: {@code users}
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
@Entity
@Table(name = "users")
public class User {
	/**
	 * Primary key (UUID).
	 * Auto-generated on insertion.
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;

	/**
	 * User email address; serves as the login identifier.
	 * Unique constraint enforced at database level.
	 * Must match Jakarta @Email validation pattern on signup.
	 */
	@Column(unique = true, nullable = false)
	private String email;

	/**
	 * BCrypt-hashed password digest.
	 * Never stored in plaintext; verified via BCrypt comparison during login.
	 */
	@Column(nullable = false)
	private String password;

	/**
	 * User's display name.
	 * Non-empty string required on signup.
	 */
	@Column(nullable = false)
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
	@ElementCollection(fetch = FetchType.EAGER)
	@CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
	@Column(name = "role")
	private List<String> roles;
}
