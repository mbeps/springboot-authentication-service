package com.maruf.auth.controller;

import com.maruf.auth.config.CookieNames;
import com.maruf.auth.config.HttpCookieFactory;
import com.maruf.auth.config.JwtSecurityProperties;
import com.maruf.auth.config.RefreshTokenSecurityProperties;
import com.maruf.auth.dto.AuthStatusResponse;
import com.maruf.auth.dto.ErrorResponse;
import com.maruf.auth.dto.LoginRequest;
import com.maruf.auth.dto.SignupRequest;
import com.maruf.auth.dto.UserResponse;
import com.maruf.auth.entity.User;
import com.maruf.auth.service.JwtService;
import com.maruf.auth.service.LocalAuthService;
import com.maruf.auth.service.RefreshTokenStore;
import com.maruf.auth.util.OAuth2AttributeExtractor;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST controller for managing authentication operations in the OAuth 2.0
 * authorization server.
 *
 * <p>
 * Provides endpoints for:
 * <ul>
 * <li>Checking current authentication status and retrieving user profile
 * information</li>
 * <li>Refreshing expired access tokens using valid refresh tokens</li>
 * <li>Discovering enabled OAuth2 providers and local authentication
 * support</li>
 * <li>Creating new user accounts via email/password registration (when
 * enabled)</li>
 * <li>Authenticating users via email/password credentials (when enabled)</li>
 * </ul>
 *
 * <p>
 * This controller manages the complete authentication lifecycle for both OAuth2
 * and local
 * authentication flows. All successful authentications initialize both an
 * access token (15 minutes)
 * and a refresh token (7 days) stored in httpOnly, secure cookies. Token
 * refresh is automatic
 * and transparent to the client application via interceptor delegation.
 *
 * <p>
 * Local authentication (email/password signup and login) is controlled by the
 * {@code app.security.local-auth.enabled} configuration flag. All endpoints
 * respond with
 * {@code ErrorResponse} on failure, allowing consistent error handling across
 * the client application.
 *
 * @see JwtService for RS256 token generation and validation
 * @see RefreshTokenStore for token persistence and blacklist management
 * @see LocalAuthService for email/password credential handling
 * @author Maruf Bepary
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

	private final JwtService jwtService;
	private final RefreshTokenStore refreshTokenStore;
	private final HttpCookieFactory cookieFactory;
	private final RefreshTokenSecurityProperties refreshTokenSecurityProperties;
	private final JwtSecurityProperties jwtSecurityProperties;
	private final InMemoryClientRegistrationRepository clientRegistrationRepository;
	private final LocalAuthService localAuthService;

	@Value("${app.security.local-auth.enabled:false}")
	private boolean localAuthEnabled;

	/**
	 * Retrieves the current authentication status and user profile information.
	 *
	 * <p>
	 * No authentication required. Returns a response indicating whether a user is
	 * currently
	 * authenticated. If authenticated, includes the user's profile (id, email,
	 * name, avatar URL).
	 * If not authenticated, returns only the {@code authenticated=false} flag. Used
	 * by the
	 * client application to hydrate its authentication state on application startup and after
	 * token refresh.
	 *
	 * @param principal the currently authenticated OAuth2 user (injected by Spring
	 *                  Security, may be null)
	 * @return a response containing the authentication status and optional user
	 *         profile
	 */
	@GetMapping("/api/auth/status")
	public ResponseEntity<AuthStatusResponse> getAuthStatus(@AuthenticationPrincipal OAuth2User principal) {
		if (principal != null) {
			UserResponse user = UserResponse.builder()
					.id(OAuth2AttributeExtractor.getUserId(principal))
					.login(OAuth2AttributeExtractor.resolveUsername(principal))
					.name(OAuth2AttributeExtractor.getName(principal))
					.email(OAuth2AttributeExtractor.getEmail(principal))
					.avatarUrl(OAuth2AttributeExtractor.getAvatarUrl(principal))
					.build();

			log.info("Auth status checked for user: {}", user.getLogin());

			return ResponseEntity.ok(
					AuthStatusResponse.builder()
							.authenticated(true)
							.user(user)
							.build());
		} else {
			log.info("Auth status checked - user not authenticated");
			return ResponseEntity.ok(
					AuthStatusResponse.builder()
							.authenticated(false)
							.build());
		}
	}

	/**
	 * Refreshes an expired access token using a valid refresh token.
	 *
	 * <p>
	 * No explicit authentication required but expects a valid {@code refresh_token}
	 * httpOnly
	 * cookie. Validates the refresh token's signature and type claim, generates a
	 * new 15-minute
	 * access token, and optionally rotates the refresh token if rotation is
	 * enabled. All token
	 * claims (id, name, email, avatar URL) are preserved during refresh.
	 *
	 * <p>
	 * Automatically called by the client's 401 interceptor when
	 * the
	 * access token has expired. Invoked by auth client (not
	 * API client).
	 *
	 * <p>
	 * <strong>Refresh token rotation behavior:</strong> If
	 * {@code app.security.refresh-token.rotation-enabled=true},
	 * the old refresh token is deleted and a new one is issued. If disabled, the
	 * same token is reused.
	 *
	 * @param request  the HTTP request containing the refresh token cookie
	 * @param response the HTTP response to which the new access token and
	 *                 optionally new refresh token will be written
	 * @return a response with success message on valid refresh, or error response
	 *         (401 or 500) on failure
	 * @throws JwtException if the refresh token signature is invalid, the token
	 *                      type is not "refresh", or the token has expired
	 * @see RefreshTokenStore#getUsernameFromRefreshToken for token validation and
	 *      lastUsed update
	 * @see JwtService for RS256 token validation and new access token generation
	 */
	@PostMapping("/api/auth/refresh")
	public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
		String refreshToken = null;
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (CookieNames.REFRESH_TOKEN.equals(cookie.getName())) {
					refreshToken = cookie.getValue();
					break;
				}
			}
		}

		if (refreshToken == null) {
			log.warn("Refresh token not found in cookies");
			return ResponseEntity.status(401)
					.body(ErrorResponse.builder()
							.error("token_missing")
							.message("Refresh token not found")
							.build());
		}

		String username = refreshTokenStore.getUsernameFromRefreshToken(refreshToken);
		if (username == null) {
			log.warn("Invalid or expired refresh token");
			return ResponseEntity.status(401)
					.body(ErrorResponse.builder()
							.error("token_invalid")
							.message("Invalid or expired refresh token")
							.build());
		}

		try {
			Claims claims = jwtService.extractAllClaims(refreshToken);

			String tokenType = (String) claims.get("type");
			if (!"refresh".equals(tokenType)) {
				log.warn("Token presented is not a refresh token");
				refreshTokenStore.invalidateRefreshToken(refreshToken);
				return ResponseEntity.status(401)
						.body(ErrorResponse.builder()
								.error("token_invalid")
								.message("Invalid token type")
								.build());
			}

			Map<String, Object> attributes = new HashMap<>();
			attributes.put("id", claims.get("id"));
			attributes.put("login", claims.getOrDefault("login", username));
			attributes.put("name", claims.get("name"));
			attributes.put("email", claims.get("email"));
			attributes.put("avatar_url", claims.get("avatar_url"));

			String newAccessToken = jwtService.generateAccessToken(attributes, (String) attributes.get("login"));

			if (refreshTokenSecurityProperties.isRotationEnabled()) {
				rotateRefreshToken(response, refreshToken, username, attributes);
			}

			cookieFactory.writeTo(response, CookieNames.JWT, newAccessToken,
					Duration.ofMillis(jwtSecurityProperties.getAccessTokenExpiration()));

			log.info("Access token refreshed for user: {}", username);

			return ResponseEntity.ok(Map.of(
					"success", true,
					"message", "Token refreshed successfully"));
		} catch (JwtException e) {
			log.warn("Refresh token is invalid or expired: {}", e.getMessage());
			refreshTokenStore.invalidateRefreshToken(refreshToken);
			return ResponseEntity.status(401)
					.body(ErrorResponse.builder()
							.error("token_expired")
							.message("Refresh token has expired")
							.build());
		} catch (Exception e) {
			log.error("Error refreshing token: {}", e.getMessage());
			return ResponseEntity.status(500)
					.body(ErrorResponse.builder()
							.error("refresh_failed")
							.message("Token refresh failed")
							.build());
		}
	}

	/**
	 * Retrieves the list of enabled OAuth2 providers and local authentication
	 * support.
	 *
	 * <p>
	 * No authentication required. Returns a list of available authentication
	 * providers
	 * configured in {@code application.yaml} (e.g., GitHub, Azure AD) plus an
	 * optional "local"
	 * provider if email/password authentication is enabled. The client application uses this
	 * endpoint
	 * to dynamically render provider buttons.
	 *
	 * @return a list of provider objects each containing a unique key (e.g.,
	 *         "github", "local")
	 *         and a display name (e.g., "GitHub", "Email & Password")
	 * @see InMemoryClientRegistrationRepository for iterating configured OAuth2
	 *      registrations
	 */
	@GetMapping("/api/auth/providers")
	public ResponseEntity<List<Map<String, String>>> getProviders() {
		List<Map<String, String>> providers = new ArrayList<>();
		clientRegistrationRepository.forEach(registration -> {
			Map<String, String> provider = new HashMap<>();
			provider.put("key", registration.getRegistrationId());
			provider.put("name", registration.getClientName());
			providers.add(provider);
		});

		if (localAuthEnabled) {
			Map<String, String> localProvider = new HashMap<>();
			localProvider.put("key", "local");
			localProvider.put("name", "Email & Password");
			providers.add(localProvider);
		}

		return ResponseEntity.ok(providers);
	}

	/**
	 * Creates a new user account with the provided email, password, and name.
	 *
	 * <p>
	 * Local authentication must be enabled
	 * ({@code app.security.local-auth.enabled=true})
	 * or this endpoint returns 403. Validates signup request body (email format,
	 * non-blank password,
	 * non-blank name). Password is BCrypt-hashed before storage. Email must be
	 * unique; duplicate
	 * emails fail with a 400 error. On successful registration, automatically
	 * authenticates the
	 * user by generating and storing both access and refresh tokens in httpOnly
	 * cookies.
	 *
	 * @param signupRequest the signup details (email, password, name) validated by
	 *                      Jakarta Validation
	 * @param response      the HTTP response to which authentication cookies will
	 *                      be written
	 * @return success response (200) with authentication tokens set in cookies, or
	 *         error response
	 *         (400 for validation/duplicate email, 403 for disabled local auth, 500
	 *         for server error)
	 * @see LocalAuthService#register for password hashing and user persistence
	 * @see #authenticateUser for token generation and cookie writing
	 * @author Maruf Bepary
	 */
	@PostMapping("/api/auth/signup")
	public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest signupRequest, HttpServletResponse response) {
		if (!localAuthEnabled) {
			return ResponseEntity.status(403).body(ErrorResponse.builder()
					.error("access_denied")
					.message("Local authentication is disabled")
					.build());
		}

		try {
			User user = localAuthService.register(signupRequest.getEmail(), signupRequest.getPassword(),
					signupRequest.getName());
			return authenticateUser(user, response);
		} catch (IllegalArgumentException e) {
			return ResponseEntity.badRequest().body(ErrorResponse.builder()
					.error("signup_failed")
					.message(e.getMessage())
					.build());
		}
	}

	/**
	 * Authenticates a user with email and password credentials.
	 *
	 * <p>
	 * Local authentication must be enabled
	 * ({@code app.security.local-auth.enabled=true})
	 * or this endpoint returns 403. Validates login request body (email format,
	 * non-blank password).
	 * Credentials are verified against BCrypt-hashed passwords stored in the
	 * database. On successful
	 * login, automatically authenticates the user by generating and storing both
	 * access and refresh
	 * tokens in httpOnly cookies. Returns 401 if credentials are invalid.
	 *
	 * @param loginRequest the login credentials (email, password) validated by
	 *                     Jakarta Validation
	 * @param response     the HTTP response to which authentication cookies will be
	 *                     written
	 * @return success response (200) with authentication tokens set in cookies, or
	 *         error response
	 *         (401 for invalid credentials, 403 for disabled local auth, 400 for
	 *         validation error, 500 for server error)
	 * @see LocalAuthService#login for BCrypt credential verification
	 * @see #authenticateUser for token generation and cookie writing
	 * @author Maruf Bepary
	 */
	@PostMapping("/api/auth/login")
	public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse response) {
		if (!localAuthEnabled) {
			return ResponseEntity.status(403).body(ErrorResponse.builder()
					.error("access_denied")
					.message("Local authentication is disabled")
					.build());
		}

		return localAuthService.login(loginRequest.getEmail(), loginRequest.getPassword())
				.<ResponseEntity<?>>map(user -> authenticateUser(user, response))
				.orElseGet(() -> ResponseEntity.status(401).body(ErrorResponse.builder()
						.error("login_failed")
						.message("Invalid email or password")
						.build()));
	}

	/**
	 * Internal helper method to complete the authentication process after
	 * successful login or signup.
	 *
	 * <p>
	 * Generates both an RS256-signed access token (15 minutes) and refresh token (7
	 * days),
	 * stores the hashed refresh token in MongoDB, and writes both tokens to
	 * httpOnly secure
	 * cookies. All user profile attributes (id, email, name, avatar URL) are
	 * encoded into
	 * the JWT claims during generation.
	 *
	 * @param user            the authenticated user entity containing profile
	 *                        information
	 * @param servletResponse the HTTP response to which authentication cookies will
	 *                        be written
	 * @return a success response with {@code success=true}
	 * @see JwtService#generateAccessToken for access token generation with user
	 *      attributes
	 * @see JwtService#generateRefreshToken for refresh token generation
	 * @see RefreshTokenStore#storeRefreshToken for persisting the refresh token
	 *      with TTL
	 * @see HttpCookieFactory#writeTo for writing secure httpOnly cookies
	 */
	private ResponseEntity<?> authenticateUser(User user, HttpServletResponse servletResponse) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("id", user.getId());
		attributes.put("login", user.getEmail());
		attributes.put("name", user.getName());
		attributes.put("email", user.getEmail());
		attributes.put("avatar_url", user.getAvatarUrl());

		String accessToken = jwtService.generateAccessToken(attributes, user.getEmail());
		String refreshToken = jwtService.generateRefreshToken(user.getEmail(), attributes);

		Instant refreshExpiresAt = Instant.now().plusMillis(jwtSecurityProperties.getRefreshTokenExpiration());
		refreshTokenStore.storeRefreshToken(refreshToken, user.getEmail(), refreshExpiresAt);

		cookieFactory.writeTo(servletResponse, CookieNames.JWT, accessToken,
				Duration.ofMillis(jwtSecurityProperties.getAccessTokenExpiration()));
		cookieFactory.writeTo(servletResponse, CookieNames.REFRESH_TOKEN, refreshToken,
				Duration.ofMillis(jwtSecurityProperties.getRefreshTokenExpiration()));

		return ResponseEntity.ok().body(Map.of("success", true));
	}

	/**
	 * Internal helper method to rotate the refresh token when enabled.
	 *
	 * <p>
	 * Invalidates the current refresh token by deleting it from the database,
	 * generates
	 * a new refresh token with the same claims, persists it to MongoDB with a new
	 * expiration
	 * time, and writes the new token to an httpOnly cookie in the response. This
	 * enhances
	 * security by limiting the window for replay attacks if a refresh token is
	 * compromised.
	 *
	 * @param response            the HTTP response to which the new refresh token
	 *                            cookie will be written
	 * @param currentRefreshToken the current refresh token value to be invalidated
	 * @param username            the associated username for logging and token
	 *                            generation
	 * @param refreshClaims       the JWT claims to preserve during rotation (id,
	 *                            name, email, avatar URL)
	 * @see RefreshTokenStore#invalidateRefreshToken for deleting the old token from
	 *      the database
	 * @see JwtService#generateRefreshToken for generating a new refresh token
	 * @see HttpCookieFactory#writeTo for writing the new token to a secure cookie
	 */
	private void rotateRefreshToken(HttpServletResponse response, String currentRefreshToken, String username,
			Map<String, Object> refreshClaims) {
		refreshTokenStore.invalidateRefreshToken(currentRefreshToken);

		String newRefreshToken = jwtService.generateRefreshToken(username, refreshClaims);
		Instant refreshExpiresAt = Instant.now().plusMillis(jwtSecurityProperties.getRefreshTokenExpiration());
		refreshTokenStore.storeRefreshToken(newRefreshToken, username, refreshExpiresAt);
		cookieFactory.writeTo(response, CookieNames.REFRESH_TOKEN, newRefreshToken,
				Duration.ofMillis(jwtSecurityProperties.getRefreshTokenExpiration()));

		log.info("Refresh token rotated for user: {}", username);
	}
}
