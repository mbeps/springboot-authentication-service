package com.maruf.auth.config;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Factory for building and writing HTTP cookies with centralized security
 * settings.
 * <p>
 * Encapsulates cookie creation logic to ensure all auth service cookies (JWT
 * and
 * refresh token) are issued with consistent security attributes from
 * {@link CookieSecurityProperties}. This abstraction eliminates duplicate
 * cookie
 * configuration code across handlers and provides a single point of control for
 * security settings like {@code httpOnly}, {@code Secure}, and
 * {@code SameSite}.
 * <p>
 * <b>Usage:</b>
 * 
 * <pre>
 * httpCookieFactory.writeTo(response, CookieNames.JWT, tokenValue, Duration.ofMinutes(15));
 * </pre>
 *
 * @author Maruf Bepary
 * @see CookieSecurityProperties
 * @see CookieNames
 * @see OAuth2AuthenticationSuccessHandler
 * @see SecurityConfig
 */
@Component
@RequiredArgsConstructor
public class HttpCookieFactory {

	private final CookieSecurityProperties cookieSecurityProperties;

	/**
	 * Builds a cookie with standard auth service security attributes.
	 * <p>
	 * Constructs a {@link ResponseCookie} with the following defaults:
	 * <ul>
	 * <li>{@code httpOnly=true} (prevents XSS token theft)</li>
	 * <li>{@code Secure} flag set according to
	 * {@link CookieSecurityProperties#isSecure()}</li>
	 * <li>{@code SameSite} policy from
	 * {@link CookieSecurityProperties#getSameSite()}</li>
	 * <li>{@code path=/} (all paths; cookies sent to entire domain)</li>
	 * <li>{@code Max-Age} set to the supplied duration</li>
	 * </ul>
	 *
	 * @param name   cookie name (e.g., {@code jwt}, {@code refresh_token})
	 * @param value  cookie value (usually a JWT or hashed token)
	 * @param maxAge time-to-live for the cookie; use {@code Duration.ZERO} to
	 *               delete
	 * @return built {@link ResponseCookie} ready for transmission
	 * @author Maruf Bepary
	 * @see CookieNames
	 */
	public ResponseCookie buildTokenCookie(String name, String value, Duration maxAge) {
		return ResponseCookie.from(name, value)
				.httpOnly(true)
				.secure(cookieSecurityProperties.isSecure())
				.sameSite(cookieSecurityProperties.getSameSite())
				.path("/")
				.maxAge(maxAge)
				.build();
	}

	/**
	 * Builds a cookie and appends it to the HTTP response.
	 * <p>
	 * Convenience method combining
	 * {@link #buildTokenCookie(String, String, Duration)}
	 * and writing to the response's {@code Set-Cookie} header in a single call.
	 * Used throughout the service when issuing or clearing cookies.
	 *
	 * @param response servlet response to which the cookie is written
	 * @param name     cookie name
	 * @param value    cookie value
	 * @param maxAge   time-to-live; use {@code Duration.ZERO} to delete the cookie
	 * @author Maruf Bepary
	 */
	public void writeTo(HttpServletResponse response, String name, String value, Duration maxAge) {
		response.addHeader(HttpHeaders.SET_COOKIE, buildTokenCookie(name, value, maxAge).toString());
	}
}
