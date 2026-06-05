package com.maruf.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for JWT token lifetimes and security parameters.
 * <p>
 * Binds properties from the application YAML file under the {@code jwt} prefix
 * to control how long JWT tokens remain valid before expiration. The access
 * token
 * has a short lifespan (typically 15 minutes) to limit damage from token
 * compromise,
 * while the refresh token has a longer lifespan (typically 7 days) to avoid
 * frequent
 * re-authentication of long-lived sessions.
 * <p>
 * <b>Example configuration:</b>
 * 
 * <pre>
 * jwt:
 *   access-token-expiration: 900000    # 15 minutes in ms
 *   refresh-token-expiration: 604800000 # 7 days in ms
 * </pre>
 * <p>
 * These durations are used throughout the authentication service when:
 * <ul>
 * <li>Generating JWT tokens via {@link com.maruf.auth.service.JwtService}</li>
 * <li>Setting HTTP cookie max-age values via {@link HttpCookieFactory}</li>
 * <li>Writing token expiration times to MongoDB via
 * {@link com.maruf.auth.service.RefreshTokenStore}</li>
 * </ul>
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.JwtService
 * @see HttpCookieFactory
 * @see com.maruf.auth.service.RefreshTokenStore
 */
@Component
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtSecurityProperties {

	/**
	 * Time-to-live for access tokens in milliseconds.
	 * <p>
	 * Access tokens carry user identity and are short-lived to limit the impact
	 * of token compromise via theft or XSS. Defaults to 900000 milliseconds (15
	 * minutes).
	 * <p>
	 * Used by:
	 * <ul>
	 * <li>{@link com.maruf.auth.service.JwtService#buildToken(java.util.Map, String, long)}
	 * to set the JWT {@code exp} claim</li>
	 * <li>{@link HttpCookieFactory#buildTokenCookie(String, String, java.time.Duration)}
	 * to set the HTTP cookie max-age</li>
	 * </ul>
	 */
	private long accessTokenExpiration = 900000;

	/**
	 * Time-to-live for refresh tokens in milliseconds.
	 * <p>
	 * Refresh tokens are long-lived and used to obtain new access tokens without
	 * requiring the user to re-authenticate with the OAuth provider. Defaults to
	 * 604800000 milliseconds (7 days). This allows users to remain logged in for
	 * extended periods while still requiring periodic revalidation.
	 * <p>
	 * Used by:
	 * <ul>
	 * <li>{@link com.maruf.auth.service.JwtService#generateRefreshToken(String, java.util.Map)}
	 * to set the JWT {@code exp} claim</li>
	 * <li>{@link com.maruf.auth.service.RefreshTokenStore#storeRefreshToken(String, String, java.time.Instant)}
	 * to set MongoDB TTL expiration</li>
	 * <li>{@link HttpCookieFactory#buildTokenCookie(String, String, java.time.Duration)}
	 * to set the HTTP cookie max-age</li>
	 * </ul>
	 */
	private long refreshTokenExpiration = 604800000;
}
