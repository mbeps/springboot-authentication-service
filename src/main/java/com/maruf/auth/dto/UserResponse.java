package com.maruf.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO containing authenticated user's profile information.
 *
 * <p>
 * Returned by multiple endpoints:
 * <ul>
 * <li>{@code GET /api/auth/status} — in the {@code user} field of
 * AuthStatusResponse</li>
 * <li>{@code GET /api/user} (resource server) — returns user profile</li>
 * </ul>
 *
 * <p>
 * The user profile data is extracted from:
 * <ul>
 * <li>JWT claims for OAuth2 authenticated users (resolved from
 * {@code OAuth2User} attributes)</li>
 * <li>User entity document for local auth authenticated users</li>
 * </ul>
 *
 * @author Maruf Bepary
 * @see AuthStatusResponse for usage context
 * @see com.maruf.auth.controller.AuthController for endpoint implementations
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
	/**
	 * Unique user identifier (MongoDB ObjectId for local users, provider-specific
	 * ID for OAuth2).
	 * Extracted from JWT {@code sub} claim or User entity id field.
	 */
	private String id;

	/**
	 * User's login/username (email for local auth, GitHub login or Azure principal
	 * ID for OAuth2).
	 * Extracted from JWT {@code login} claim or User entity email field.
	 */
	private String login;

	/**
	 * User's full display name.
	 * Extracted from JWT {@code name} claim or User entity name field.
	 * May contain spaces and special characters (no normalization).
	 */
	private String name;

	/**
	 * User's email address.
	 * Extracted from JWT {@code email} claim or User entity email field.
	 * Guaranteed to be a valid email format.
	 */
	private String email;

	/**
	 * User's profile picture URL (e.g., GitHub avatar or Microsoft/Entra ID
	 * picture).
	 * May be null for users without a profile image.
	 * Extracted from JWT {@code avatarUrl} claim or User entity avatarUrl field.
	 */
	private String avatarUrl;
}
