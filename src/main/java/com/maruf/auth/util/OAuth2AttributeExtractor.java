package com.maruf.auth.util;

import com.maruf.auth.exception.InsufficientScopeException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;

/**
 * Utility class providing provider-agnostic extraction and normalization of
 * standard
 * user attributes from an {@link OAuth2User} returned by the OAuth2 login flow.
 * <p>
 * <b>Problem:</b> Different identity providers use non-standard or conflicting
 * attribute names. For example, GitHub uses {@code "login"} while Azure AD uses
 * {@code "preferred_username"}; GitHub uses {@code "id"} while Azure uses
 * {@code "oid"}.
 * <p>
 * <b>Solution:</b> This class encapsulates a multi-key fallback strategy,
 * allowing
 * the rest of the application to work with a consistent set of logical
 * attributes:
 * {@code id}, {@code login}, {@code name}, {@code email}, {@code avatar_url},
 * and {@code username}.
 * <p>
 * <b>Attribute Extraction Strategy:</b>
 * <ul>
 * <li><b>User ID:</b> Tries {@code id}, {@code oid}, {@code sub}</li>
 * <li><b>Login/Username:</b> Tries {@code login}, {@code preferred_username},
 * {@code upn}, {@code email}</li>
 * <li><b>Name:</b> Tries {@code name}, {@code displayName}</li>
 * <li><b>Email:</b> Tries {@code email}, {@code preferred_username} (if
 * contains '@'),
 * or extracts the first item from a {@code emails} collection</li>
 * <li><b>Avatar URL:</b> Tries {@code avatar_url}, then {@code picture}</li>
 * </ul>
 * <p>
 * <b>Validation:</b> The {@link #validateRequiredAttributes(OAuth2User)} method
 * enforces that both a user ID and login/email are present. If either is
 * missing,
 * an {@link InsufficientScopeException} is thrown, indicating that the OAuth
 * scope
 * was insufficient for the required identity information.
 * <p>
 * <b>Usage:</b> All methods are static; the class cannot be instantiated.
 * Typical usage:
 * 
 * <pre>
 * OAuth2User principal = ...; // From authentication context
 * OAuth2AttributeExtractor.validateRequiredAttributes(principal);
 * String username = OAuth2AttributeExtractor.resolveUsername(principal);
 * String email = OAuth2AttributeExtractor.getEmail(principal);
 * </pre>
 *
 * @author Maruf Bepary
 * @see InsufficientScopeException
 * @see OAuth2User
 * @see org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
 */
public final class OAuth2AttributeExtractor {

	private OAuth2AttributeExtractor() {
	}

	/**
	 * Extracts the provider-specific user identifier.
	 * <p>
	 * Checks attributes in order: {@code id} (GitHub), {@code oid} (Azure AD),
	 * {@code sub} (generic OIDC). Returns {@code null} if none are present,
	 * indicating that user ID information was not included in the OAuth response—
	 * likely due to insufficient OAuth scope configuration.
	 *
	 * @param principal OAuth2User provided by Spring Security during OAuth login
	 * @return user identifier as a string, or {@code null} if none found
	 * @author Maruf Bepary
	 */
	public static String getUserId(OAuth2User principal) {
		Object id = principal.getAttribute("id");
		if (id != null)
			return id.toString();

		Object oid = principal.getAttribute("oid");
		if (oid != null)
			return oid.toString();

		Object sub = principal.getAttribute("sub");
		if (sub != null)
			return sub.toString();

		return null;
	}

	/**
	 * Retrieves a login/username identifier from the provider.
	 * <p>
	 * Attempts extraction in order: {@code login} (GitHub),
	 * {@code preferred_username}
	 * (Azure AD), {@code upn} (generic Active Directory), {@code email} (fallback).
	 * Returns {@code null} if none are found, typically due to missing or
	 * insufficient
	 * OAuth scopes (e.g. the provider did not return the {@code user:email} scope
	 * for GitHub).
	 *
	 * @param principal OAuth2User to inspect
	 * @return login/username string, or {@code null} if none available
	 * @author Maruf Bepary
	 */
	public static String getLogin(OAuth2User principal) {
		Object login = principal.getAttribute("login");
		if (login != null)
			return login.toString();

		Object preferredUsername = principal.getAttribute("preferred_username");
		if (preferredUsername != null)
			return preferredUsername.toString();

		Object upn = principal.getAttribute("upn");
		if (upn != null)
			return upn.toString();

		Object email = principal.getAttribute("email");
		if (email != null)
			return email.toString();

		return null;
	}

	/**
	 * Extracts the user's display name from the provider attributes.
	 * <p>
	 * Checks attributes in order: {@code name} (standard), {@code displayName}
	 * (Azure AD). Returns {@code null} if neither is present.
	 *
	 * @param principal OAuth2User instance
	 * @return display name, or {@code null} if not available
	 * @author Maruf Bepary
	 */
	public static String getName(OAuth2User principal) {
		Object name = principal.getAttribute("name");
		if (name != null)
			return name.toString();

		Object displayName = principal.getAttribute("displayName");
		if (displayName != null)
			return displayName.toString();

		return null;
	}

	/**
	 * Extracts an email address from the provider.
	 * <p>
	 * Checks attributes in order: {@code email} (standard),
	 * {@code preferred_username}
	 * from Azure AD (only if it contains '@'), or the first item in an
	 * {@code emails}
	 * collection (as a fallback). Returns {@code null} if none are available or if
	 * the collection is empty.
	 *
	 * @param principal OAuth2User provided by the authentication process
	 * @return email address, or {@code null} if not found
	 * @author Maruf Bepary
	 */
	public static String getEmail(OAuth2User principal) {
		Object email = principal.getAttribute("email");
		if (email != null)
			return email.toString();

		Object preferredUsername = principal.getAttribute("preferred_username");
		if (preferredUsername != null && preferredUsername.toString().contains("@"))
			return preferredUsername.toString();

		Object emails = principal.getAttribute("emails");
		if (emails instanceof Collection<?>) {
			return ((Collection<?>) emails).stream()
					.findFirst()
					.map(Object::toString)
					.orElse(null);
		}

		return null;
	}

	/**
	 * Looks up the user's avatar or profile picture URL.
	 * <p>
	 * Checks attributes in order: {@code avatar_url} (GitHub), {@code picture}
	 * (generic OIDC/Azure). Returns {@code null} if neither is present.
	 *
	 * @param principal from which to read avatar or picture URL
	 * @return image URL, or {@code null} if not available
	 * @author Maruf Bepary
	 */
	public static String getAvatarUrl(OAuth2User principal) {
		Object avatarUrl = principal.getAttribute("avatar_url");
		if (avatarUrl != null)
			return avatarUrl.toString();

		Object picture = principal.getAttribute("picture");
		if (picture != null)
			return picture.toString();

		return null;
	}

	/**
	 * Resolves a suitable application username by prioritizing available
	 * attributes.
	 * <p>
	 * Attempts to return a username in order of preference: login/username (via
	 * {@link #getLogin(OAuth2User)}), then email (via
	 * {@link #getEmail(OAuth2User)}),
	 * then user ID (via {@link #getUserId(OAuth2User)}). Returns {@code null} only
	 * if all three fallbacks are absent—a rare condition that typically indicates
	 * an OAuth scope or provider configuration issue.
	 *
	 * @param principal OAuth2User instance
	 * @return resolved username string, or {@code null} if no suitable attribute
	 *         found
	 * @author Maruf Bepary
	 */
	public static String resolveUsername(OAuth2User principal) {
		String username = getLogin(principal);
		if (username != null)
			return username;

		username = getEmail(principal);
		if (username != null)
			return username;

		return getUserId(principal);
	}

	/**
	 * Validates that the principal contains the minimal set of attributes
	 * required for authentication.
	 * <p>
	 * Enforces two requirements:
	 * <ol>
	 * <li>User ID must be present (checked via {@link #getUserId(OAuth2User)})</li>
	 * <li>Login/username must be present (checked via
	 * {@link #getLogin(OAuth2User)})</li>
	 * </ol>
	 * <p>
	 * If either is missing, throws {@link InsufficientScopeException} with a
	 * specific message indicating the missing attribute. This exception should
	 * be caught at the OAuth2 authentication handler level and result in a
	 * user-friendly error or redirect to request additional scopes from the
	 * provider.
	 *
	 * @param principal OAuth2User to validate
	 * @throws InsufficientScopeException if user ID or login is missing
	 * @author Maruf Bepary
	 */
	public static void validateRequiredAttributes(OAuth2User principal) {
		String userId = getUserId(principal);
		String login = getLogin(principal);

		if (userId == null) {
			throw new InsufficientScopeException("Missing user identifier - OAuth provider did not return user ID");
		}

		if (login == null) {
			throw new InsufficientScopeException("Missing username/email - required scope may not have been granted");
		}
	}
}
