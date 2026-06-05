package com.maruf.auth.config;

import com.maruf.auth.service.JwtService;
import com.maruf.auth.service.RefreshTokenStore;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;

/**
 * Spring Security configuration for the authentication service.
 * <p>
 * Defines a stateless filter chain that handles CORS, disables CSRF, and
 * applies JWT verification via {@link JwtAuthenticationFilter}. OAuth2 login
 * endpoints are exposed with custom request resolvers and success/failure
 * handlers that integrate with the cookie-based token issuance flow. Logout is
 * also customised to blacklist tokens and clear cookies. Public API paths are
 * permitted while all others require authentication.
 * <p>
 * <strong>Filter Chain Order (Critical):</strong>
 * <ol>
 * <li>CORS validation</li>
 * <li>CSRF disabled (stateless API)</li>
 * <li>Session management set to STATELESS</li>
 * <li>Path-based authorization matchers</li>
 * <li>Exception handling (JSON 401 for API, redirect for browser)</li>
 * <li>OAuth2 login customization (custom resolver, success/failure
 * handlers)</li>
 * <li>Logout handler (token invalidation and cookie clearing)</li>
 * <li>{@link JwtAuthenticationFilter} inserted before
 * {@link UsernamePasswordAuthenticationFilter}</li>
 * </ol>
 * <p>
 * <strong>Path Authorization:</strong>
 * <ul>
 * <li>{@code /}, {@code /error}, {@code /webjars/**} — public (landing, error,
 * Swagger UI)</li>
 * <li>{@code /oauth2/**}, {@code /login/**} — public (OAuth2 flow
 * endpoints)</li>
 * <li>{@code /api/auth/**} — public (status, login, signup, refresh,
 * providers)</li>
 * <li>{@code /logout} — public (allows logout without active auth; tokens
 * validated inside handler)</li>
 * <li>{@code /.well-known/jwks.json} — public (JWKS key distribution for
 * verification)</li>
 * <li>All other paths — require authentication</li>
 * </ul>
 * <p>
 * <strong>Logout & Token Invalidation:</strong> The logout handler has two
 * responsibilities:
 * <ul>
 * <li>Blacklist the access token in {@code invalidated_access_tokens} via
 * {@link RefreshTokenStore#invalidateAccessToken(String, String, java.time.Instant)}
 * (prevents token reuse even if cached by client).</li>
 * <li>Delete the refresh token from {@code refresh_tokens} via
 * {@link RefreshTokenStore#invalidateRefreshToken(String)}
 * (prevents new access token issuance).</li>
 * <li>Clear both cookies by setting {@code maxAge=0} via
 * {@link HttpCookieFactory}.</li>
 * </ul>
 * Errors during invalidation are logged as WARN but do not block the response.
 *
 * @author Maruf Bepary
 * @see JwtAuthenticationFilter
 * @see OAuth2AuthenticationSuccessHandler
 * @see OAuth2AuthenticationFailureHandler
 * @see CustomOAuth2AuthorizationRequestResolver
 * @see HttpCookieOAuth2AuthorizationRequestRepository
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

	private final AuthSecurityProperties authSecurityProperties;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;
	private final OAuth2AuthenticationFailureHandler oauth2FailureHandler;
	private final RefreshTokenStore refreshTokenStore;
	private final JwtService jwtService;
	private final HttpCookieFactory cookieFactory;
	private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;
	private final ClientRegistrationRepository clientRegistrationRepository;

	/**
	 * Password encoder bean used for local authentication.
	 * <p>
	 * BCrypt is chosen for hashing user passwords before storage in MongoDB.
	 * This bean is autowired into {@link com.maruf.auth.service.LocalAuthService}.
	 *
	 * @return a {@link PasswordEncoder} instance
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * Creates the custom OAuth2 authorization request resolver that understands
	 * the {@code redirect_uri} query parameter and enforces the whitelist of
	 * allowed redirect URLs. Used by the OAuth2 login flow.
	 *
	 * @return configured resolver instance
	 */
	@Bean
	public CustomOAuth2AuthorizationRequestResolver authorizationRequestResolver() {
		return new CustomOAuth2AuthorizationRequestResolver(
				clientRegistrationRepository,
				authSecurityProperties.getAllowedRedirectUrls());
	}

	/**
	 * Defines the main security filter chain for HTTP requests.
	 * <p>
	 * Configures CORS, stateless sessions, permitted endpoints, exception
	 * handling, OAuth2 login customization, logout behavior (including token
	 * invalidation and cookie clearing), and registers the JWT authentication
	 * filter.
	 *
	 * @param http HttpSecurity builder
	 * @return constructed {@link SecurityFilterChain}
	 * @throws Exception if configuration fails
	 */
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.cors(cors -> cors.configurationSource(corsConfigurationSource()))
				.csrf(csrf -> csrf.disable())
				.sessionManagement(session -> session
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(authz -> authz
						.requestMatchers("/", "/error", "/webjars/**").permitAll()
						.requestMatchers("/oauth2/**", "/login/**").permitAll()
						.requestMatchers("/api/auth/**").permitAll()
						.requestMatchers("/logout").permitAll()
						.requestMatchers("/.well-known/jwks.json").permitAll()
						.anyRequest().authenticated())
				.exceptionHandling(exceptions -> exceptions
						.authenticationEntryPoint(apiAuthenticationEntryPoint()))
				.oauth2Login(oauth2 -> oauth2
						.authorizationEndpoint(authEndpoint -> authEndpoint
								.authorizationRequestRepository(authorizationRequestRepository)
								.authorizationRequestResolver(authorizationRequestResolver()))
						.successHandler(oauth2SuccessHandler)
						.failureHandler(oauth2FailureHandler))
				.logout(logout -> logout
						.logoutUrl("/logout")
						.logoutSuccessHandler((request, response, authentication) -> {
							if (request.getCookies() != null) {
								for (Cookie cookie : request.getCookies()) {
									try {
										if (CookieNames.JWT.equals(cookie.getName())) {
											String token = cookie.getValue();
											if (jwtService.isTokenValid(token)) {
												java.time.Instant expiresAt = jwtService.getExpirationDate(token)
														.toInstant();
												String username = jwtService.extractUsername(token);
												refreshTokenStore.invalidateAccessToken(token, username, expiresAt);
											}
										} else if (CookieNames.REFRESH_TOKEN.equals(cookie.getName())) {
											refreshTokenStore.invalidateRefreshToken(cookie.getValue());
										}
									} catch (Exception e) {
										log.warn("Failed to invalidate token during logout: {}", e.getMessage());
									}
								}
							}

							cookieFactory.writeTo(response, CookieNames.JWT, "", Duration.ZERO);
							cookieFactory.writeTo(response, CookieNames.REFRESH_TOKEN, "", Duration.ZERO);

							response.setStatus(200);
							response.setContentType("application/json");
							response.getWriter().write("{\"success\":true,\"message\":\"Logout successful\"}");
						})
						.deleteCookies(CookieNames.JWT, CookieNames.REFRESH_TOKEN))
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	/**
	 * CORS configuration source allowing origins defined in
	 * {@link AuthSecurityProperties#getAllowedOrigins()} and standard HTTP
	 * methods. Credentials (cookies) are permitted.
	 *
	 * @return CORS configuration source bean
	 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(authSecurityProperties.getAllowedOrigins());
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	/**
	 * Custom authentication entry point that returns JSON 401 responses for
	 * API endpoints and redirects to the login page for browser requests.
	 *
	 * @return {@link AuthenticationEntryPoint} used in exception handling
	 */
	@Bean
	public AuthenticationEntryPoint apiAuthenticationEntryPoint() {
		return (request, response, authException) -> {
			String requestUri = request.getRequestURI();
			if (requestUri != null && requestUri.startsWith("/api/")) {
				response.setStatus(HttpStatus.UNAUTHORIZED.value());
				response.setContentType("application/json");
				response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Authentication required\"}");
			} else {
				response.sendRedirect("/login");
			}
		};
	}
}
