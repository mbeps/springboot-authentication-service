package com.maruf.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request DTO for the local user signup endpoint
 * ({@code POST /api/auth/signup}).
 *
 * <p>
 * Accepts new user registration details: email, password, and full name.
 * On successful signup, creates a new User entity with BCrypt-hashed password
 * and initializes refresh/access tokens.
 *
 * <p>
 * Validation:
 * <ul>
 * <li>{@code email}: Must be a valid email format and non-blank</li>
 * <li>{@code password}: Must be non-blank</li>
 * <li>{@code name}: Must be non-blank</li>
 * </ul>
 *
 * <p>
 * Success response: Cookies set; returns {@code {success:true}}.
 * Failure responses:
 * <ul>
 * <li>400: Invalid email format or missing required field</li>
 * <li>403: Email already registered (user exists) or local auth is
 * disabled</li>
 * </ul>
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.LocalAuthService for registration logic
 * @see com.maruf.auth.controller.AuthController#signup(SignupRequest) for
 *      endpoint implementation
 */
@Data
public class SignupRequest {
	/**
	 * New user's email address (login identifier).
	 * Constraints: Must be non-blank and valid email format (RFC 5322 via
	 * Jakarta @Email).
	 * Must be unique; attempting to register an existing email returns 403
	 * Forbidden.
	 */
	@NotBlank
	@Email
	private String email;

	/**
	 * New user's plaintext password to be BCrypt-hashed on storage.
	 * Constraints: Must be non-blank.
	 * No minimum length enforced at DTO level; actual password strength validation
	 * should be added at the service layer if required.
	 */
	@NotBlank
	private String password;

	/**
	 * New user's full name (display name).
	 * Constraints: Must be non-blank.
	 * Stored as-is in the User entity; no case normalization or trimming enforced.
	 */
	@NotBlank
	private String name;
}
