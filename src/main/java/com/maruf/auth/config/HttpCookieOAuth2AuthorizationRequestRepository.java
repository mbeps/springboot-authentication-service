package com.maruf.auth.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.io.*;
import java.time.Duration;
import java.util.Base64;

/**
 * Stateless OAuth2 authorization request storage using HTTP cookies.
 * <p>
 * <b>Purpose:</b> Replaces Spring Security's default server-side session-based
 * storage with a client-side cookie mechanism. This enables stateless OAuth2
 * flows
 * where the authorization request and state are carried entirely in cookies.
 * <p>
 * <b>How It Works:</b>
 * <ul>
 * <li>When an OAuth2 login is initiated ({@link #saveAuthorizationRequest}),
 * the {@link OAuth2AuthorizationRequest} object is serialized to binary,
 * Base64 URL-encoded, and stored in a cookie named
 * {@code oauth2_auth_request}.</li>
 * <li>When the OAuth2 callback is processed
 * ({@link #loadAuthorizationRequest}),
 * the cookie is retrieved, decoded, and deserialized back to the original
 * object.</li>
 * <li>The cookie expires after 180 seconds, limiting the risk of state replay
 * attacks.</li>
 * </ul>
 * <p>
 * <b>Integration:</b> Registered in {@link SecurityConfig} as the
 * {@code AuthorizationRequestRepository} for OAuth2 login configuration.
 * <p>
 * <b>Advantages over session storage:</b>
 * <ul>
 * <li>No server-side session management required</li>
 * <li>Stateless operation—multiple service instances can verify the same state
 * cookie</li>
 * <li>CSRF protection: state is tied to the browser's cookie jar via
 * SameSite</li>
 * </ul>
 *
 * @author Maruf Bepary
 * @see SecurityConfig
 * @see CustomOAuth2AuthorizationRequestResolver
 * @see OAuth2AuthenticationSuccessHandler
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class HttpCookieOAuth2AuthorizationRequestRepository

		implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

	/**
	 * Name of the cookie used to store the OAuth2 authorization request.
	 */
	private static final String COOKIE_NAME = "oauth2_auth_request";

	/**
	 * Expiration time for the authorization request cookie, in seconds.
	 * <p>
	 * Set to 180 seconds (3 minutes) to allow adequate time for the user to
	 * authenticate with the OAuth2 provider while limiting the validity window
	 * for state replay attacks.
	 */
	private static final int COOKIE_EXPIRE_SECONDS = 180;

	private final HttpCookieFactory cookieFactory;

	/**
	 * Retrieves the OAuth2 authorization request from the cookie.
	 * <p>
	 * Searches for the {@code oauth2_auth_request} cookie, deserializes its Base64
	 * URL-decoded value, and returns the {@link OAuth2AuthorizationRequest}.
	 * Returns {@code null} if the cookie is not found.
	 *
	 * @param request current HTTP servlet request
	 * @return deserialized authorization request, or {@code null} if not found or
	 *         if
	 *         deserialization fails
	 * @author Maruf Bepary
	 */
	@Override
	public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		return getCookieValue(request);
	}

	/**
	 * Stores an OAuth2 authorization request in a cookie.
	 * <p>
	 * If {@code authorizationRequest} is {@code null}, the authorization request
	 * cookie is deleted (by calling {@link #removeCookie(HttpServletResponse)}).
	 * Otherwise, the request object is serialized, Base64 URL-encoded, and stored
	 * in a cookie with {@link #COOKIE_EXPIRE_SECONDS} expiration via
	 * {@link HttpCookieFactory#writeTo(HttpServletResponse, String, String, Duration)}.
	 *
	 * @param authorizationRequest the authorization request to store, or
	 *                             {@code null} to delete
	 * @param request              current HTTP servlet request
	 * @param response             servlet response to which the cookie is written
	 * @author Maruf Bepary
	 */
	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
			HttpServletResponse response) {
		if (authorizationRequest == null) {
			removeCookie(response);
			return;
		}
		String serialized = serialize(authorizationRequest);
		cookieFactory.writeTo(response, COOKIE_NAME, serialized, Duration.ofSeconds(COOKIE_EXPIRE_SECONDS));
	}

	/**
	 * Loads and removes the OAuth2 authorization request from the cookie.
	 * <p>
	 * Retrieves the authorization request via
	 * {@link #loadAuthorizationRequest(HttpServletRequest)},
	 * then deletes the cookie if the request was found.
	 *
	 * @param request  current HTTP servlet request
	 * @param response servlet response to which cookie deletion is written
	 * @return the deserialized authorization request if found, or {@code null}
	 *         otherwise
	 * @author Maruf Bepary
	 */
	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
			HttpServletResponse response) {
		OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);
		if (authorizationRequest != null) {
			removeCookie(response);
		}
		return authorizationRequest;
	}

	/**
	 * Extracts the authorization request from the {@code oauth2_auth_request}
	 * cookie.
	 * <p>
	 * Iterates through request cookies to find the one matching
	 * {@link #COOKIE_NAME},
	 * then attempts to deserialize its value.
	 *
	 * @param request current HTTP servlet request
	 * @return deserialized authorization request, or {@code null} if not found or
	 *         if
	 *         deserialization fails
	 * @author Maruf Bepary
	 */
	private OAuth2AuthorizationRequest getCookieValue(HttpServletRequest request) {
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (COOKIE_NAME.equals(cookie.getName())) {
					return deserialize(cookie.getValue());
				}
			}
		}
		return null;
	}

	/**
	 * Clears the authorization request cookie by setting its max-age to zero.
	 *
	 * @param response servlet response to which the cookie deletion is written
	 * @author Maruf Bepary
	 */
	private void removeCookie(HttpServletResponse response) {
		cookieFactory.writeTo(response, COOKIE_NAME, "", Duration.ZERO);
	}

	/**
	 * Serializes an {@link OAuth2AuthorizationRequest} to a Base64 URL-encoded
	 * string.
	 * <p>
	 * Uses Java object serialization (ObjectOutputStream) followed by Base64 URL
	 * encoding without padding, suitable for transmission in HTTP cookies.
	 *
	 * @param request the authorization request to serialize
	 * @return Base64 URL-encoded string representation
	 * @throws IllegalStateException if serialization fails (wrapped IOException)
	 * @author Maruf Bepary
	 */
	private String serialize(OAuth2AuthorizationRequest request) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(bos)) {
			oos.writeObject(request);
			return Base64.getUrlEncoder().withoutPadding().encodeToString(bos.toByteArray());
		} catch (IOException e) {
			log.error("Failed to serialize OAuth2 authorization request", e);
			throw new IllegalStateException("Failed to serialize authorization request", e);
		}
	}

	/**
	 * Deserializes a Base64 URL-encoded string into an
	 * {@link OAuth2AuthorizationRequest}.
	 * <p>
	 * Reverses the {@link #serialize(OAuth2AuthorizationRequest)} operation by
	 * decoding
	 * the Base64 URL string and using ObjectInputStream to reconstruct the request
	 * object.
	 *
	 * @param value Base64 URL-encoded serialized request
	 * @return deserialized {@link OAuth2AuthorizationRequest}, or {@code null} if
	 *         decoding or deserialization fails
	 * @author Maruf Bepary
	 */
	private OAuth2AuthorizationRequest deserialize(String value) {
		try {
			byte[] bytes = Base64.getUrlDecoder().decode(value);
			try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
					ObjectInputStream ois = new ObjectInputStream(bis)) {
				return (OAuth2AuthorizationRequest) ois.readObject();
			}
		} catch (IOException | ClassNotFoundException e) {
			log.error("Failed to deserialize OAuth2 authorization request", e);
			return null;
		}
	}
}
