package com.maruf.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request DTO for the local email/password login endpoint
 * ({@code POST /api/auth/login}).
 *
 * <p>
 * Accepts user credentials and authenticates via BCrypt password verification.
 * On successful authentication, generates RS256-signed JWT tokens and sets
 * httpOnly cookies.
 *
 * <p>
 * Validation:
 * <ul>
 * <li>{@code email}: Must be a valid email format and non-blank</li>
 * <li>{@code password}: Must be non-blank (no length limit at DTO level)</li>
 * </ul>
 *
 * <p>
 * Success response: Cookies set; returns {@code {success:true}}.
 * Failure responses:
 * <ul>
 * <li>400: Invalid email format or missing required field</li>
 * <li>401: Email not found or password mismatch</li>
 * <li>403: Local auth is disabled
 * ({@code app.security.local-auth.enabled=false})</li>
 * </ul>
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.LocalAuthService for credential validation
 * @see com.maruf.auth.controller.AuthController#login(LoginRequest) for
 *      endpoint implementation
 */
@Data
public class LoginRequest {
	/**
	 * User's email address (login identifier).
	 * Constraints: Must be non-blank and valid email format (RFC 5322 via
	 * Jakarta @Email).
	 * Only emails with existing entries in the users table can authenticate.
	 */
	@NotBlank
	@Email
	private String email;

	/**
	 * Raw plaintext password to be verified against the BCrypt hash stored in the
	 * User entity.
	 * Constraints: Must be non-blank.
	 * Not validated for minimum length at DTO level (validation happens at service
	 * layer).
	 */
	@NotBlank
	private String password;
}
