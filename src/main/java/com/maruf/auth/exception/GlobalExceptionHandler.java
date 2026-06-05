package com.maruf.auth.exception;

import com.maruf.auth.dto.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler providing centralized error handling across the
 * authentication service.
 * <p>
 * <b>Purpose:</b> Catches exceptions from any controller or filter, logs them
 * appropriately,
 * and returns standardized error responses with proper HTTP status codes. This
 * ensures all
 * API clients receive consistent error information regardless of where
 * exceptions originate.
 * <p>
 * <b>Handled Exceptions:</b>
 * <ul>
 * <li>{@link MethodArgumentNotValidException} → 400 Bad Request with
 * field-level errors</li>
 * <li>{@link AuthenticationException} → 401 Unauthorized</li>
 * <li>{@link AccessDeniedException} → 403 Forbidden</li>
 * <li>{@link IllegalArgumentException} → 400 Bad Request</li>
 * <li>{@link InsufficientScopeException} → 403 Forbidden</li>
 * <li>Generic {@link Exception} → 500 Internal Server Error</li>
 * </ul>
 * <p>
 * <b>Logging:</b> Each handler logs the error at WARN or ERROR level, providing
 * server-side visibility for debugging and monitoring. Detailed stack traces
 * are
 * logged for errors but not returned to the client.
 *
 * @author Maruf Bepary
 * @see InsufficientScopeException
 * @see com.maruf.auth.dto.ErrorResponse
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

	/**
	 * Handles Jakarta Bean Validation (Validation) constraint violations.
	 * <p>
	 * Extracts field-level error messages and returns them in a 400 response body
	 * with timestamp and status code. Used when request body parameters fail
	 * validation.
	 *
	 * @param ex the validation exception
	 * @return 400 Bad Request response with field errors
	 * @author Maruf Bepary
	 */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidationErrors(MethodArgumentNotValidException ex) {
		Map<String, String> errors = new HashMap<>();
		ex.getBindingResult().getAllErrors().forEach(error -> {
			String fieldName = ((FieldError) error).getField();
			String errorMessage = error.getDefaultMessage();
			errors.put(fieldName, errorMessage);
		});

		Map<String, Object> response = new HashMap<>();
		response.put("timestamp", LocalDateTime.now());
		response.put("status", HttpStatus.BAD_REQUEST.value());
		response.put("error", "Validation Failed");
		response.put("errors", errors);

		log.warn("Validation error: {}", errors);
		return ResponseEntity.badRequest().body(response);
	}

	/**
	 * Handles authentication-related exceptions.
	 * <p>
	 * Returns a 401 Unauthorized response when authentication fails (e.g., invalid
	 * credentials, missing token, or JWT validation errors).
	 *
	 * @param ex the authentication exception
	 * @return 401 Unauthorized response
	 * @author Maruf Bepary
	 */
	@ExceptionHandler(AuthenticationException.class)
	public ResponseEntity<Map<String, Object>> handleAuthenticationException(AuthenticationException ex) {
		Map<String, Object> response = new HashMap<>();
		response.put("timestamp", LocalDateTime.now());
		response.put("status", HttpStatus.UNAUTHORIZED.value());
		response.put("error", "Authentication Failed");
		response.put("message", ex.getMessage());

		log.warn("Authentication error: {}", ex.getMessage());
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
	}

	/**
	 * Handles authorization failures (insufficient permissions).
	 * <p>
	 * Returns a 403 Forbidden response when an authenticated user attempts to
	 * access
	 * a resource they do not have permission for.
	 *
	 * @param ex the access denied exception
	 * @return 403 Forbidden response
	 * @author Maruf Bepary
	 */
	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<Map<String, Object>> handleAccessDeniedException(AccessDeniedException ex) {
		Map<String, Object> response = new HashMap<>();
		response.put("timestamp", LocalDateTime.now());
		response.put("status", HttpStatus.FORBIDDEN.value());
		response.put("error", "Access Denied");
		response.put("message", "You don't have permission to access this resource");

		log.warn("Access denied: {}", ex.getMessage());
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
	}

	/**
	 * Handles illegal argument exceptions.
	 * <p>
	 * Returns a 400 Bad Request response for invalid arguments, such as a
	 * non-whitelisted redirect URI in the OAuth2 flow.
	 *
	 * @param ex the illegal argument exception
	 * @return 400 Bad Request response
	 * @author Maruf Bepary
	 */
	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(IllegalArgumentException ex) {
		Map<String, Object> response = new HashMap<>();
		response.put("timestamp", LocalDateTime.now());
		response.put("status", HttpStatus.BAD_REQUEST.value());
		response.put("error", "Bad Request");
		response.put("message", ex.getMessage());

		log.warn("Illegal argument: {}", ex.getMessage());
		return ResponseEntity.badRequest().body(response);
	}

	/**
	 * Handles all unhandled exceptions (fallback handler).
	 * <p>
	 * Returns a generic 500 Internal Server Error response. The actual exception
	 * message is not returned to the client for security; only a generic message
	 * is provided. Full details are logged server-side for debugging.
	 *
	 * @param ex any unhandled exception
	 * @return 500 Internal Server Error response
	 * @author Maruf Bepary
	 */
	@ExceptionHandler(Exception.class)
	public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
		Map<String, Object> response = new HashMap<>();
		response.put("timestamp", LocalDateTime.now());
		response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
		response.put("error", "Internal Server Error");
		response.put("message", "An unexpected error occurred");

		log.error("Unexpected error: ", ex);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
	}

	/**
	 * Handles OAuth2 scope validation failures.
	 * <p>
	 * Returns a 403 Forbidden response when required user attributes are missing
	 * from the OAuth2 provider response, typically due to insufficient OAuth scopes
	 * being requested during the authorization handshake.
	 *
	 * @param ex the insufficient scope exception
	 * @return 403 Forbidden response with error details
	 * @author Maruf Bepary
	 * @see InsufficientScopeException
	 */
	@ExceptionHandler(InsufficientScopeException.class)
	public ResponseEntity<ErrorResponse> handleInsufficientScopeException(InsufficientScopeException ex) {
		ErrorResponse response = ErrorResponse.builder()
				.error("insufficient_scope")
				.message(ex.getMessage())
				.build();

		log.warn("Insufficient OAuth scope: {}", ex.getMessage());
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
	}
}
