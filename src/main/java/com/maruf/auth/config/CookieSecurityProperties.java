package com.maruf.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for HTTP cookie security attributes.
 * <p>
 * Binds properties from the application YAML file under the {@code cookie}
 * prefix
 * to control how all auth-related cookies (JWT and refresh token) are issued.
 * These settings are injected into {@link HttpCookieFactory} to ensure
 * consistent
 * security behavior across all cookie responses.
 * <p>
 * <b>Example configuration:</b>
 * 
 * <pre>
 * cookie:
 *   secure: true        # HTTPS-only (true in production)
 *   same-site: Strict   # SameSite policy
 * </pre>
 *
 * @author Maruf Bepary
 * @see HttpCookieFactory
 * @see SecurityConfig
 */
@Component
@ConfigurationProperties(prefix = "cookie")
@Data
public class CookieSecurityProperties {

	/**
	 * Whether cookies should be sent only over HTTPS.
	 * <p>
	 * Set to {@code true} in production to enforce secure (HTTPS-only)
	 * transmission.
	 * Defaults to {@code false} for local development. Controls the {@code Secure}
	 * flag in {@code Set-Cookie} headers.
	 */
	private boolean secure = false;

	/**
	 * SameSite attribute value for cookies.
	 * <p>
	 * Mitigates CSRF attacks. Valid values are {@code "Strict"}, {@code "Lax"}
	 * (default), or {@code "None"}. When set to {@code "None"}, {@link #secure}
	 * must be {@code true} and cookies are sent with cross-site requests.
	 * Defaults to {@code "Lax"}.
	 */
	private String sameSite = "Lax";
}
