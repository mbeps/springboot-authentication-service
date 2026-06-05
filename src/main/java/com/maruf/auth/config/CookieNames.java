package com.maruf.auth.config;

/**
 * Constants used for cookie names throughout the authentication service.
 * <p>
 * These strings are the keys for the {@code jwt} access token and
 * {@code refresh_token} cookies that the service issues to clients. Using a
 * constants class avoids magic strings in filters, controllers and handlers.
 */
public final class CookieNames {

	/** Name of the HTTP-only access token cookie. */
	public static final String JWT = "jwt";
	/** Name of the HTTP-only refresh token cookie. */
	public static final String REFRESH_TOKEN = "refresh_token";

	private CookieNames() {
	}
}
