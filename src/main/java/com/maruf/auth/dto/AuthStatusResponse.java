package com.maruf.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for the authentication status endpoint
 * ({@code GET /api/auth/status}).
 *
 * <p>
 * Returned by the auth service to indicate whether the current request is
 * authenticated
 * and (optionally) provide the authenticated user's profile information. This
 * endpoint is
 * called by the client application on initial page load to hydrate the
 * application's authentication state.
 *
 * <p>
 * Contract:
 * <ul>
 * <li>If {@code authenticated=true}, {@code user} will be populated with the
 * current user's details</li>
 * <li>If {@code authenticated=false}, {@code user} will be null</li>
 * </ul>
 *
 * @author Maruf Bepary
 * @see UserResponse for user payload structure
 * @see com.maruf.auth.controller.AuthController#getAuthStatus() for endpoint
 *      implementation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthStatusResponse {
	/**
	 * Whether the request contains a valid, non-expired JWT access token.
	 * True if the jwt cookie is present and passes validation; false otherwise.
	 */
	private boolean authenticated;

	/**
	 * The authenticated user's profile information.
	 * Non-null only when {@code authenticated=true}.
	 * Extracted from JWT claims: {@code id}, {@code login}, {@code name},
	 * {@code email}, {@code avatarUrl}.
	 * 
	 * @see UserResponse for field details
	 */
	private UserResponse user;
}
