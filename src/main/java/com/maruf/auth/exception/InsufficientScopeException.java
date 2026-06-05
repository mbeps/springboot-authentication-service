package com.maruf.auth.exception;

/**
 * Exception thrown when an OAuth2 provider response lacks required user
 * attributes.
 * <p>
 * <b>When It's Thrown:</b> During OAuth2 authentication, after the identity
 * provider
 * returns user information,
 * {@link com.maruf.auth.util.OAuth2AttributeExtractor#validateRequiredAttributes(org.springframework.security.oauth2.core.user.OAuth2User)}
 * checks that critical attributes (user ID and login/username) are present. If
 * either
 * is missing, this exception is raised.
 * <p>
 * <b>Root Cause:</b> Typically indicates that the OAuth2 scopes requested
 * during the
 * authorization handshake were insufficient. For example:
 * <ul>
 * <li><b>GitHub:</b> {@code user:email} scope is missing, so {@code email} and
 * {@code login}
 * attributes are not returned by GitHub.</li>
 * <li><b>Azure AD:</b> {@code profile} or {@code User.Read} scope is
 * missing.</li>
 * </ul>
 * <p>
 * <b>How It's Handled:</b>
 * <ul>
 * <li>Caught by
 * {@link com.maruf.auth.config.OAuth2AuthenticationSuccessHandler} during
 * the OAuth2 login flow.</li>
 * <li>User is redirected to the frontend with {@code ?error=missing_scope}
 * query parameter.</li>
 * <li>Caught by {@link GlobalExceptionHandler} if thrown from other contexts,
 * returning
 * a 403 Forbidden response with error details.</li>
 * </ul>
 * <p>
 * <b>Example:</b>
 * 
 * <pre>
 * if (userId == null) {
 * 	throw new InsufficientScopeException(
 * 			"Missing user identifier - OAuth provider did not return user ID");
 * }
 * </pre>
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.util.OAuth2AttributeExtractor
 * @see com.maruf.auth.config.OAuth2AuthenticationSuccessHandler
 * @see GlobalExceptionHandler
 */
public class InsufficientScopeException extends RuntimeException {

	/**
	 * Constructs a new exception with the specified detail message.
	 *
	 * @param message the detail message explaining which attribute is missing
	 * @author Maruf Bepary
	 */
	public InsufficientScopeException(String message) {
		super(message);
	}

	/**
	 * Constructs a new exception with the specified detail message and cause.
	 *
	 * @param message the detail message
	 * @param cause   the underlying exception that triggered this exception
	 * @author Maruf Bepary
	 */
	public InsufficientScopeException(String message, Throwable cause) {
		super(message, cause);
	}
}
