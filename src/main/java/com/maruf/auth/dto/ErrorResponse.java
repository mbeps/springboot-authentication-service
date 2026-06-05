package com.maruf.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Standard error response DTO returned by all API endpoints on failure.
 *
 * <p>
 * Includes a machine-readable error code and a human-readable error message.
 * Used by {@code GlobalExceptionHandler} to format exception responses
 * consistently
 * across all endpoints (HTTP 400, 401, 403, 500, etc.).
 *
 * <p>
 * Example response body (400 validation error):
 * 
 * <pre>
 * {
 *   "error": "VALIDATION_FAILED",
 *   "message": "email must be a valid email address"
 * }
 * </pre>
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.exception.GlobalExceptionHandler for usage
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse {
	/**
	 * Machine-readable error code (e.g., "VALIDATION_FAILED", "UNAUTHORIZED",
	 * "USER_EXISTS", "AUTH_FAILED").
	 * Used by the client application to conditionally display error messages or trigger specific
	 * actions.
	 */
	private String error;

	/**
	 * Human-readable error description.
	 * Examples: "email must be a valid email address", "user already exists",
	 * "invalid credentials".
	 */
	private String message;
}
