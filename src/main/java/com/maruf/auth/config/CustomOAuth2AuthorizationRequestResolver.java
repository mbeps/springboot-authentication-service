package com.maruf.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Base64;
import java.util.List;

/**
 * Custom OAuth2 authorization request resolver supporting dynamic redirect URI
 * validation.
 * <p>
 * <b>Problem:</b> Spring Security's default authorization request resolver does
 * not support
 * passing the desired post-login redirect URL as a query parameter. This makes
 * it difficult
 * to support multiple client origins (staging, production, local development)
 * from the same
 * service.
 * <p>
 * <b>Solution:</b> This resolver intercepts the OAuth2 authorization request,
 * extracts and
 * validates a {@code redirect_uri} query parameter against a whitelist, then
 * embeds it into
 * the OAuth2 state parameter using Base64 URL encoding. The downstream
 * {@link OAuth2AuthenticationSuccessHandler} decodes and uses this URI to
 * redirect the user
 * to the correct client URL.
 * <p>
 * <b>Flow:</b>
 * <ol>
 * <li>Client application initiates OAuth:
 * {@code GET /oauth2/authorization/{id}?redirect_uri={url}}</li>
 * <li>This resolver validates {@code redirect_uri} against the whitelist</li>
 * <li>If valid, appends Base64-encoded redirect to the OAuth2 state:
 * {@code state:encodedUri}</li>
 * <li>If invalid, throws {@code IllegalArgumentException} (caught by error
 * handler)</li>
 * <li>Browser is redirected to OAuth2 provider with customized state</li>
 * <li>After provider redirects back, {@link OAuth2AuthenticationSuccessHandler}
 * retrieves
 * the original {@code redirect_uri} from the state</li>
 * </ol>
 * <p>
 * <b>Security Note:</b> The whitelist prevents open redirects. All redirect
 * URIs must start
 * with a configured allowed URL to be accepted.
 *
 * @author Maruf Bepary
 * @see OAuth2AuthenticationSuccessHandler
 * @see SecurityConfig
 * @see AuthSecurityProperties
 */
@Slf4j
public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

	private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
	private final List<String> allowedRedirectUrls;

	public CustomOAuth2AuthorizationRequestResolver(
			ClientRegistrationRepository clientRegistrationRepository,
			List<String> allowedRedirectUrls) {
		this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
				clientRegistrationRepository, "/oauth2/authorization");
		this.allowedRedirectUrls = allowedRedirectUrls;
	}

	/**
	 * Resolves an OAuth2 authorization request without a specific client
	 * registration ID.
	 * <p>
	 * Delegates to the default resolver and then customizes the request by
	 * extracting
	 * and validating the {@code redirect_uri} query parameter.
	 *
	 * @param request current HTTP servlet request
	 * @return customized {@link OAuth2AuthorizationRequest}, or {@code null} if the
	 *         default
	 *         resolver returns {@code null}
	 * @throws IllegalArgumentException if {@code redirect_uri} is provided but not
	 *                                  in the whitelist
	 * @author Maruf Bepary
	 */
	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
		return customizeAuthorizationRequest(request, authorizationRequest);
	}

	/**
	 * Resolves an OAuth2 authorization request for a specific client registration.
	 * <p>
	 * Delegates to the default resolver using the provided
	 * {@code clientRegistrationId},
	 * then customizes the request by extracting and validating the
	 * {@code redirect_uri}
	 * query parameter.
	 *
	 * @param request              current HTTP servlet request
	 * @param clientRegistrationId registration ID of the OAuth2 client (e.g.,
	 *                             {@code github}, {@code azure})
	 * @return customized {@link OAuth2AuthorizationRequest}, or {@code null} if the
	 *         default
	 *         resolver returns {@code null}
	 * @throws IllegalArgumentException if {@code redirect_uri} is provided but not
	 *                                  in the whitelist
	 * @author Maruf Bepary
	 */
	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);
		return customizeAuthorizationRequest(request, authorizationRequest);
	}

	/**
	 * Customizes the OAuth2 authorization request with the redirect URI if
	 * provided.
	 * <p>
	 * Extracts the {@code redirect_uri} query parameter, validates it against the
	 * allowed list, and if valid, appends it to the OAuth2 state parameter in the
	 * format: {@code originalState:base64UrlEncodedRedirectUri}.
	 *
	 * @param request              current HTTP servlet request
	 * @param authorizationRequest authorization request to customize (may be
	 *                             {@code null})
	 * @return customized authorization request with embedded redirect URI, or the
	 *         original
	 *         request if no {@code redirect_uri} parameter is provided
	 * @throws IllegalArgumentException if {@code redirect_uri} is provided but not
	 *                                  whitelisted
	 * @author Maruf Bepary
	 */
	private OAuth2AuthorizationRequest customizeAuthorizationRequest(
			HttpServletRequest request, OAuth2AuthorizationRequest authorizationRequest) {
		if (authorizationRequest == null) {
			return null;
		}

		String redirectUri = request.getParameter("redirect_uri");
		if (redirectUri != null && !redirectUri.isBlank()) {
			if (!isAllowedRedirectUrl(redirectUri)) {
				log.warn("Rejected unauthorized redirect_uri: {}", redirectUri);
				throw new IllegalArgumentException("Unauthorized redirect URI");
			}

			String originalState = authorizationRequest.getState();
			String encodedRedirect = Base64.getUrlEncoder().withoutPadding()
					.encodeToString(redirectUri.getBytes());
			String customState = originalState + ":" + encodedRedirect;

			return OAuth2AuthorizationRequest.from(authorizationRequest)
					.state(customState)
					.build();
		}

		return authorizationRequest;
	}

	/**
	 * Validates whether a URL is whitelisted for OAuth2 redirect.
	 * <p>
	 * Checks if the supplied URL starts with any of the configured allowed redirect
	 * URLs from {@link AuthSecurityProperties#getAllowedRedirectUrls()}.
	 *
	 * @param url URL to validate (typically a client base URL)
	 * @return {@code true} if the URL starts with an allowed prefix, {@code false}
	 *         otherwise
	 * @author Maruf Bepary
	 */
	private boolean isAllowedRedirectUrl(String url) {
		return allowedRedirectUrls.stream().anyMatch(url::startsWith);
	}
}
