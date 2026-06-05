package com.maruf.auth.config;

import com.maruf.auth.service.JwtService;
import com.maruf.auth.service.RefreshTokenStore;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Servlet filter that authenticates requests by validating a JWT stored in the
 * {@code jwt} cookie.
 * <p>
 * <b>Filter Lifecycle:</b> Executes once per request as a
 * {@link OncePerRequestFilter} registered before Spring's
 * {@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter}.
 * <p>
 * <b>Validation Logic:</b> For each request, the filter:
 * <ol>
 * <li>Extracts the JWT from the {@code jwt} cookie via
 * {@link CookieNames#JWT}</li>
 * <li>Checks if the token is blacklisted (revoked) via
 * {@link RefreshTokenStore#isAccessTokenInvalidated(String)}</li>
 * <li>Verifies token signature and expiration with
 * {@link JwtService#isTokenValid(String)}</li>
 * <li>Ensures the token type claim is exactly {@code "access"} (rejects refresh
 * tokens)</li>
 * <li>Extracts claims and attributes from the valid token</li>
 * <li>Constructs a {@link DefaultOAuth2User} and populates
 * {@link SecurityContextHolder} with an authenticated authentication
 * object</li>
 * </ol>
 * <p>
 * <b>Security Constraints:</b> Tokens in the blacklist are rejected even if
 * otherwise
 * valid. This supports logout and token revocation. Only tokens with
 * {@code type="access"} are accepted; refresh tokens are rejected. If any
 * validation step fails, the request continues unauthenticated and downstream
 * authorization rules determine access.
 *
 * @author Maruf Bepary
 * @see JwtService
 * @see RefreshTokenStore
 * @see CookieNames
 * @see DefaultOAuth2User
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final RefreshTokenStore refreshTokenStore;

	/**
	 * Main filter execution logic invoked once per request.
	 * <p>
	 * Attempts to extract, validate, and apply a JWT token from the request.
	 * If successful, populates the {@link SecurityContextHolder} with an
	 * authenticated
	 * principal. Blacklisted tokens are silently rejected and treated as
	 * unauthenticated.
	 * Any validation error is logged and the request continues without
	 * authentication.
	 *
	 * @param request     incoming HTTP servlet request
	 * @param response    HTTP servlet response
	 * @param filterChain filter chain to continue processing
	 * @throws ServletException if the filter or downstream filters encounter a
	 *                          servlet error
	 * @throws IOException      if input/output error occurs during processing
	 * @author Maruf Bepary
	 */
	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {

		String jwt = extractJwtFromCookie(request);

		if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			try {
				if (refreshTokenStore.isAccessTokenInvalidated(jwt)) {
					log.debug("JWT is invalidated");
					filterChain.doFilter(request, response);
					return;
				}

				if (jwtService.isTokenValid(jwt)) {
					String tokenType = jwtService.extractTokenType(jwt);
					if (!"access".equals(tokenType)) {
						log.debug("Token is not an access token");
						filterChain.doFilter(request, response);
						return;
					}

					Claims claims = jwtService.extractAllClaims(jwt);

					Map<String, Object> attributes = extractAttributesFromClaims(claims);

					OAuth2User oauth2User = new DefaultOAuth2User(
							Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
							attributes,
							"login");

					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
							oauth2User,
							null,
							oauth2User.getAuthorities());

					authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authentication);

					log.debug("JWT validated for user: {}", claims.get("login"));
				}
			} catch (Exception e) {
				log.error("JWT validation failed: {}", e.getMessage());
			}
		}

		filterChain.doFilter(request, response);
	}

	/**
	 * Extracts the JWT value from the {@code jwt} cookie in the request.
	 * <p>
	 * Iterates through all cookies in the request to find the one matching
	 * {@link CookieNames#JWT}. Returns the cookie value or {@code null} if not
	 * present.
	 *
	 * @param request current servlet request
	 * @return JWT token string, or {@code null} if the {@code jwt} cookie is absent
	 * @author Maruf Bepary
	 */
	private String extractJwtFromCookie(HttpServletRequest request) {
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (CookieNames.JWT.equals(cookie.getName())) {
					return cookie.getValue();
				}
			}
		}
		return null;
	}

	/**
	 * Converts JWT claims into a map of attributes for OAuth2User construction.
	 * <p>
	 * Extracts standard user attributes from the JWT claims (id, login, name,
	 * email,
	 * avatar_url) and populates a map. The {@code id} claim is cast to an integer
	 * if it is numeric; other claims are converted to strings. Null or absent
	 * claims
	 * are skipped.
	 *
	 * @param claims JWT claims parsed from the validated token
	 * @return map of attribute names to values suitable for
	 *         {@link DefaultOAuth2User}
	 * @author Maruf Bepary
	 */
	private Map<String, Object> extractAttributesFromClaims(Claims claims) {
		Map<String, Object> attributes = new HashMap<>();

		Object idClaim = claims.get("id");
		if (idClaim instanceof Number) {
			attributes.put("id", ((Number) idClaim).intValue());
		} else if (idClaim != null) {
			attributes.put("id", idClaim);
		}

		addIfNotNull(attributes, "login", claims.get("login"));
		addIfNotNull(attributes, "name", claims.get("name"));
		addIfNotNull(attributes, "email", claims.get("email"));
		addIfNotNull(attributes, "avatar_url", claims.get("avatar_url"));

		return attributes;
	}

	/**
	 * Conditionally adds a claim value to the attributes map.
	 * <p>
	 * If the value is non-null, it is placed in the map under the given key.
	 * Used to safely populate the attributes map while avoiding null entries.
	 *
	 * @param attributes map to which the key-value pair is added
	 * @param key        attribute name
	 * @param value      claim value (may be null)
	 * @author Maruf Bepary
	 */
	private void addIfNotNull(Map<String, Object> attributes, String key, Object value) {
		if (value != null) {
			attributes.put(key, value);
		}
	}
}
