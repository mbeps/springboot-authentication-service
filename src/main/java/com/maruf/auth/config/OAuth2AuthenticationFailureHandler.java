package com.maruf.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Handler invoked when OAuth2 login fails.
 * <p>
 * <b>Purpose:</b> Provides custom error handling for failed OAuth2
 * authentication attempts,
 * including failures due to user denial, provider errors, or misconfigured
 * scopes.
 * <p>
 * <b>Behavior:</b> Logs the error details at ERROR level and redirects the
 * user's browser
 * to the configured client application URL with {@code ?error=auth_failed} query
 * parameter, allowing
 * the client application to display a user-friendly error message.
 * <p>
 * <b>Integration:</b> Registered in {@link SecurityConfig} as the failure
 * handler for
 * OAuth2 login configuration.
 *
 * @author Maruf Bepary
 * @see SecurityConfig
 * @see OAuth2AuthenticationSuccessHandler
 * @see AuthSecurityProperties
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	private final AuthSecurityProperties authSecurityProperties;

	/**
	 * Callback invoked after OAuth2 authentication failure.
	 * <p>
	 * <b>Behavior:</b>
	 * <ol>
	 * <li>If the exception is an {@link OAuth2AuthenticationException}, extracts
	 * and logs
	 * the error code and description</li>
	 * <li>For other authentication exceptions, logs a generic failure message</li>
	 * <li>Redirects to the first allowed client application URL from
	 * {@link AuthSecurityProperties#getAllowedRedirectUrls()}
	 * with {@code ?error=auth_failed} appended</li>
	 * </ol>
	 * <p>
	 * The client application receives the error parameter and may display the appropriate
	 * message
	 * to the user or offer retry options.
	 *
	 * @param request   current servlet request (contains OAuth2 callback
	 *                  parameters)
	 * @param response  current servlet response used to perform the redirect
	 * @param exception the authentication exception that caused the failure
	 * @throws IOException if the redirect cannot be performed
	 * @author Maruf Bepary
	 */
	@Override
	public void onAuthenticationFailure(HttpServletRequest request,
			HttpServletResponse response,
			AuthenticationException exception) throws IOException {
		if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
			log.error("OAuth2 authentication failed: {} - details: {}", oauth2Exception.getError().getErrorCode(),
					oauth2Exception.getError().getDescription(), oauth2Exception);
		} else {
			log.error("Authentication failed: {}", exception.getMessage(), exception);
		}

		String redirectUrl = authSecurityProperties.getAllowedRedirectUrls().get(0);
		getRedirectStrategy().sendRedirect(request, response,
				redirectUrl + "/?error=auth_failed");
	}
}
