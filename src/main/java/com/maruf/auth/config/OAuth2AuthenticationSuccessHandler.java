package com.maruf.auth.config;

import com.maruf.auth.exception.InsufficientScopeException;
import com.maruf.auth.service.JwtService;
import com.maruf.auth.service.RefreshTokenStore;
import com.maruf.auth.util.OAuth2AttributeExtractor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Success handler for OAuth2 logins.
 * <p>
 * After a user successfully authenticates with a third-party provider, this
 * handler validates required attributes, generates RS256-signed access and
 * refresh tokens via {@link JwtService}, stores the refresh token in PostgreSQL
 * (with optional hashing/rotation), writes cookies, and finally redirects the
 * user to the appropriate client application {@code /dashboard} URL. The original
 * {@code redirect_uri} is carried inside the OAuth2 state parameter.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private final JwtService jwtService;
	private final RefreshTokenStore refreshTokenStore;
	private final HttpCookieFactory cookieFactory;
	private final AuthSecurityProperties authSecurityProperties;
	private final JwtSecurityProperties jwtSecurityProperties;

	/**
	 * Callback invoked after successful OAuth2 authentication.
	 * <p>
	 * <b>Responsibilities:</b>
	 * <ol>
	 * <li>Validates that required user attributes (ID and login) are present via
	 * {@link OAuth2AttributeExtractor#validateRequiredAttributes(OAuth2User)}
	 * </li>
	 * <li>Generates an RS256-signed access token via
	 * {@link JwtService#generateAccessToken(OAuth2User)}
	 * </li>
	 * <li>Generates an RS256-signed refresh token with detailed user claims via
	 * {@link JwtService#generateRefreshToken(String, java.util.Map)}
	 * </li>
	 * <li>Persists the refresh token to PostgreSQL via
	 * {@link RefreshTokenStore#storeRefreshToken(String, String, java.time.Instant)}
	 * </li>
	 * <li>Writes both tokens as {@code httpOnly} cookies via
	 * {@link HttpCookieFactory#writeTo(jakarta.servlet.http.HttpServletResponse, String, String, java.time.Duration)}
	 * </li>
	 * <li>Decodes the original {@code redirect_uri} from the OAuth2 state parameter
	 * and validates it against the configured allow list
	 * </li>
	 * <li>Redirects the browser to {@code {redirectUrl}/dashboard}
	 * </li>
	 * </ol>
	 * <p>
	 * <b>Error Handling:</b> If validation fails or required attributes are
	 * missing,
	 * the user is redirected to the configured client application URL with an error query
	 * parameter:
	 * <ul>
	 * <li>{@code ?error=missing_scope} — required OAuth scope was not granted</li>
	 * <li>{@code ?error=missing_profile} — unable to determine a username from
	 * attributes</li>
	 * </ul>
	 *
	 * @param request        incoming servlet request with OAuth2 callback
	 *                       parameters
	 * @param response       servlet response used to write cookies and perform
	 *                       redirect
	 * @param authentication authentication object containing the authenticated
	 *                       OAuth2User
	 * @throws IOException if redirect operation fails
	 * @author Maruf Bepary
	 * @see OAuth2AttributeExtractor
	 * @see JwtService
	 * @see RefreshTokenStore
	 * @see HttpCookieFactory
	 * @see CustomOAuth2AuthorizationRequestResolver
	 */
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		String redirectUrl = resolveRedirectUrl(request);

		try {
			OAuth2AttributeExtractor.validateRequiredAttributes(oauth2User);
		} catch (InsufficientScopeException e) {
			log.warn("OAuth scope validation failed: {}", e.getMessage());
			getRedirectStrategy().sendRedirect(request, response, redirectUrl + "/?error=missing_scope");
			return;
		}

		String username = OAuth2AttributeExtractor.resolveUsername(oauth2User);
		if (username == null) {
			log.error("Unable to determine username from OAuth2 attributes: {}", oauth2User.getAttributes());
			getRedirectStrategy().sendRedirect(request, response, redirectUrl + "/?error=missing_profile");
			return;
		}

		String accessToken = jwtService.generateAccessToken(oauth2User);

		Map<String, Object> refreshClaims = new HashMap<>();
		refreshClaims.put("id", OAuth2AttributeExtractor.getUserId(oauth2User));
		refreshClaims.put("login", username);
		refreshClaims.put("name", OAuth2AttributeExtractor.getName(oauth2User));
		refreshClaims.put("email", OAuth2AttributeExtractor.getEmail(oauth2User));
		refreshClaims.put("avatar_url", OAuth2AttributeExtractor.getAvatarUrl(oauth2User));
		String refreshToken = jwtService.generateRefreshToken(username, refreshClaims);

		Instant refreshExpiresAt = Instant.now().plusMillis(jwtSecurityProperties.getRefreshTokenExpiration());
		refreshTokenStore.storeRefreshToken(refreshToken, username, refreshExpiresAt);

		cookieFactory.writeTo(response, CookieNames.JWT, accessToken,
				Duration.ofMillis(jwtSecurityProperties.getAccessTokenExpiration()));
		cookieFactory.writeTo(response, CookieNames.REFRESH_TOKEN, refreshToken,
				Duration.ofMillis(jwtSecurityProperties.getRefreshTokenExpiration()));

		log.info("Access and refresh tokens generated for user: {}", username);

		getRedirectStrategy().sendRedirect(request, response, redirectUrl + "/dashboard");
	}

	/**
	 * Decodes the original {@code redirect_uri} from the OAuth2 state
	 * parameter if present and verifies it against the whitelist. Falls back to
	 * the first allowed redirect URL configured in properties.
	 *
	 * @param request current HTTP request
	 * @return validated redirect URL
	 */
	private String resolveRedirectUrl(HttpServletRequest request) {
		String state = request.getParameter("state");
		if (state != null && state.contains(":")) {
			try {
				String encodedRedirect = state.substring(state.indexOf(":") + 1);
				String redirectUri = new String(Base64.getUrlDecoder().decode(encodedRedirect));
				if (isAllowedRedirectUrl(redirectUri)) {
					return redirectUri;
				}
				log.warn("Redirect URI from state is not in allowed list: {}", redirectUri);
			} catch (Exception e) {
				log.warn("Failed to decode redirect URI from state: {}", e.getMessage());
			}
		}
		return authSecurityProperties.getAllowedRedirectUrls().get(0);
	}

	/**
	 * Checks whether the supplied URL starts with one of the configured allowed
	 * redirect URLs.
	 *
	 * @param url URL to validate
	 * @return {@code true} if allowed, {@code false} otherwise
	 */
	private boolean isAllowedRedirectUrl(String url) {
		return authSecurityProperties.getAllowedRedirectUrls().stream()
				.anyMatch(url::startsWith);
	}
}
