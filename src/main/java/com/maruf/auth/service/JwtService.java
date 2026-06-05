package com.maruf.auth.service;

import com.maruf.auth.config.JwtSecurityProperties;
import com.maruf.auth.util.OAuth2AttributeExtractor;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Manages JWT token lifecycle using RS256 asymmetric cryptography.
 * <p>
 * This service is responsible for all JWT operations in the authentication
 * system:
 * <ul>
 * <li><strong>Token Generation:</strong> Creates signed access and refresh
 * tokens
 * using RSA private key (RS256 algorithm). All tokens include standard claims
 * (iat, exp, sub) plus custom claims (id, login, name, email, avatar_url,
 * type).
 * <li><strong>Token Validation:</strong> Verifies token signature and
 * expiration
 * using RSA public key. Returns false for any invalid/malformed tokens.
 * <li><strong>Key Management:</strong> Loads RSA private and public keys from
 * PEM files at startup via {@link #init()}. Throws
 * {@link IllegalStateException}
 * if keys cannot be loaded (fail-fast approach ensures startup failures are
 * immediate and obvious).
 * <li><strong>Public Key Distribution:</strong> Exposes {@link #getPublicKey()}
 * for
 * external services (e.g., resource servers) to verify tokens without access to
 * the private key. This implements the JWKS (RFC 7517) pattern.
 * </ul>
 * <p>
 * <strong>Security Notes:</strong>
 * <ul>
 * <li>The private key is never exported; it remains in-memory and is used only
 * for signing operations performed within this service.
 * <li>All tokens carry a "type" claim ("access" or "refresh") to prevent misuse
 * (e.g., refresh tokens cannot be used as access tokens).
 * <li>Access tokens default to 15-minute expiration; refresh tokens default to
 * 7 days. These values are configured via {@link JwtSecurityProperties}.
 * <li>Token validation performs signature verification first; expiration is
 * checked separately and returns false if expired.
 * </ul>
 * <p>
 * <strong>RS256 Cryptographic Details:</strong> RS256 (RSA Signature with
 * SHA-256)
 * uses an RSA key pair. The private key signs JWT payloads, producing a
 * signature
 * that can only be verified with the corresponding public key. This asymmetry
 * is
 * critical: resource servers can verify tokens without ever holding the private
 * key,
 * making it impossible for a compromised service to forge valid tokens.
 *
 * @author Maruf Bepary
 * @see JwtSecurityProperties
 * @see OAuth2AttributeExtractor
 * @see com.maruf.auth.config.JwtAuthenticationFilter
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

	@Value("${jwt.private-key-path}")
	private String privateKeyPath;

	@Value("${jwt.public-key-path}")
	private String publicKeyPath;

	private final JwtSecurityProperties jwtSecurityProperties;

	private RSAPrivateKey rsaPrivateKey;
	private RSAPublicKey rsaPublicKey;

	/**
	 * Initializes the JWT service by loading RSA key pair from PEM files.
	 * <p>
	 * Called automatically by Spring at bean construction time
	 * ({@code @PostConstruct}). Loads the private key from
	 * {@code jwt.private-key-path} and public key from
	 * {@code jwt.public-key-path}. Both keys must be in standard PEM format
	 * (PKCS8 for private, X509 for public). Throws {@link IllegalStateException}
	 * if either key file cannot be read or parsed, causing application startup
	 * to fail immediately.
	 *
	 * @throws IllegalStateException if RSA keys cannot be loaded or are invalid
	 */
	@PostConstruct
	public void init() {
		try {
			this.rsaPrivateKey = loadPrivateKey(privateKeyPath);
			this.rsaPublicKey = loadPublicKey(publicKeyPath);
			log.info("RSA key pair loaded successfully");
		} catch (Exception e) {
			throw new IllegalStateException("Failed to load RSA keys", e);
		}
	}

	/**
	 * Generates a signed access token from OAuth2 user attributes.
	 * <p>
	 * Extracts user profile information (id, login, name, email, avatar_url)
	 * from the {@link OAuth2User} and creates an access token with these claims.
	 * The token is signed with RS256 (RSA private key) and includes the
	 * {@code type="access"} claim to prevent refresh token misuse.
	 *
	 * @param oauth2User the authenticated OAuth2 user
	 * @return signed JWT access token
	 * @throws IllegalStateException if unable to extract username from OAuth2
	 *                               attributes
	 * @see #generateAccessToken(Map, String)
	 * @see com.maruf.auth.config.OAuth2AuthenticationSuccessHandler
	 */
	public String generateAccessToken(OAuth2User oauth2User) {
		String username = OAuth2AttributeExtractor.resolveUsername(oauth2User);
		if (username == null) {
			throw new IllegalStateException("Unable to determine username from OAuth2 user");
		}
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", OAuth2AttributeExtractor.getUserId(oauth2User));
		claims.put("login", username);
		claims.put("name", OAuth2AttributeExtractor.getName(oauth2User));
		claims.put("email", OAuth2AttributeExtractor.getEmail(oauth2User));
		claims.put("avatar_url", OAuth2AttributeExtractor.getAvatarUrl(oauth2User));
		return generateAccessToken(claims, username);
	}

	/**
	 * Generates a signed access token with explicit claims and subject.
	 * <p>
	 * Creates a short-lived access token (default 15 minutes) with the provided
	 * claims and subject (usually username/email). Automatically adds the
	 * {@code type="access"} claim and standard JWT claims (iat, exp, sub).
	 * Uses RS256 (RSA private key) for signing.
	 *
	 * @param claims  a map of custom claims to include in the token
	 * @param subject the JWT subject (typically the username or email)
	 * @return signed JWT access token
	 * @see #generateRefreshToken(String, Map)
	 * @see com.maruf.auth.service.RefreshTokenStore
	 */
	public String generateAccessToken(Map<String, Object> claims, String subject) {
		Map<String, Object> tokenClaims = new HashMap<>(claims);
		tokenClaims.put("type", "access");
		return buildToken(tokenClaims, subject, jwtSecurityProperties.getAccessTokenExpiration());
	}

	/**
	 * Generates a signed refresh token for session renewal.
	 * <p>
	 * Creates a long-lived refresh token (default 7 days) with the
	 * {@code type="refresh"} claim and any additional claims provided.
	 * Refresh tokens are used by the client to obtain new access tokens
	 * without re-authenticating. Used RS256 (RSA private key) for signing.
	 * <p>
	 * Refresh tokens are typically hashed via
	 * {@link com.maruf.auth.service.RefreshTokenStore#applyHash(String)} before
	 * storage in MongoDB to prevent token theft via database breach.
	 *
	 * @param username         the subject (username or email) of the token
	 * @param additionalClaims optional custom claims to include
	 * @return signed JWT refresh token
	 * @see #generateAccessToken(Map, String)
	 * @see com.maruf.auth.service.RefreshTokenStore#storeRefreshToken
	 */
	public String generateRefreshToken(String username, Map<String, Object> additionalClaims) {
		Map<String, Object> claims = new HashMap<>(additionalClaims);
		claims.put("type", "refresh");
		return buildToken(claims, username, jwtSecurityProperties.getRefreshTokenExpiration());
	}

	/**
	 * Builds and signs a JWT token using RS256.
	 * <p>
	 * Internal method that constructs the final JWT token. Sets the claims,
	 * subject, issued-at time (current), and expiration. Signs with the
	 * RSA private key using RS256 algorithm. The resulting compact JWT string
	 * is in the format: {@code header.payload.signature}.
	 *
	 * @param claims     map of claims to include (may include "type" claim)
	 * @param subject    the JWT subject (typically username)
	 * @param expiration expiration duration in milliseconds
	 * @return compact, signed JWT token
	 */
	private String buildToken(Map<String, Object> claims, String subject, long expiration) {
		return Jwts.builder()
				.claims(claims)
				.subject(subject)
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(rsaPrivateKey)
				.compact();
	}

	/**
	 * Extracts and verifies all claims from a JWT token.
	 * <p>
	 * Parses the JWT and verifies its signature using the RSA public key.
	 * Returns the payload claims if the signature is valid. Throws an exception
	 * if the token is malformed, the signature is invalid, or parsing fails.
	 * This method performs signature verification; expiration checking must
	 * be done separately via {@link #isTokenExpired(String)}.
	 *
	 * @param token the JWT token to parse
	 * @return all claims (payload) from the token
	 * @throws io.jsonwebtoken.JwtException if the token is invalid or signature
	 *                                      verification fails
	 * @see #isTokenValid(String)
	 * @see #getExpirationDate(String)
	 */
	public Claims extractAllClaims(String token) {
		return Jwts.parser()
				.verifyWith(rsaPublicKey)
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

	/**
	 * Extracts the subject claim from a JWT token.
	 * <p>
	 * Parses the token and returns the "sub" (subject) claim, which typically
	 * contains the username or email. Returns null if the subject claim is not
	 * present. Verification of the signature is performed as part of claims
	 * extraction.
	 *
	 * @param token the JWT token
	 * @return the subject claim value (usually username or email)
	 * @throws io.jsonwebtoken.JwtException if the token is invalid
	 * @see #extractTokenType(String)
	 */
	public String extractUsername(String token) {
		return extractAllClaims(token).getSubject();
	}

	/**
	 * Extracts the token type claim from a JWT token.
	 * <p>
	 * Returns the "type" claim, which is either "access" or "refresh".
	 * Used by filters and controllers to enforce that access tokens are used
	 * for API requests and refresh tokens are used only for renewal operations.
	 *
	 * @param token the JWT token
	 * @return the type claim value ("access" or "refresh")
	 * @throws io.jsonwebtoken.JwtException if the token is invalid
	 * @see #extractUsername(String)
	 * @see com.maruf.auth.config.JwtAuthenticationFilter
	 */
	public String extractTokenType(String token) {
		return (String) extractAllClaims(token).get("type");
	}

	/**
	 * Validates a JWT token's signature and structure.
	 * <p>
	 * Attempts to parse and verify the token signature using the RSA public key.
	 * Returns true if the signature is valid and the token is well-formed; returns
	 * false if any exception occurs (malformed, invalid signature, etc.). This
	 * method does NOT check expiration; use {@link #isTokenExpired(String)} for
	 * that. Errors are logged at ERROR level for debugging.
	 *
	 * @param token the JWT token to validate
	 * @return true if the token signature is valid, false otherwise
	 * @see #isTokenExpired(String)
	 * @see #extractAllClaims(String)
	 */
	public boolean isTokenValid(String token) {
		try {
			extractAllClaims(token);
			return true;
		} catch (Exception e) {
			log.error("Invalid JWT token: {}", e.getMessage());
			return false;
		}
	}

	/**
	 * Checks if a JWT token has expired.
	 * <p>
	 * Extracts the expiration time from the token and compares it against the
	 * current system time. Returns true if the token's expiration date is in
	 * the past. Returns true on any exception (e.g., invalid token), treating
	 * invalid tokens as expired.
	 *
	 * @param token the JWT token to check
	 * @return true if the token has expired, false if still valid
	 * @see #isTokenValid(String)
	 * @see #getExpirationDate(String)
	 */
	public boolean isTokenExpired(String token) {
		try {
			return extractAllClaims(token).getExpiration().before(new Date());
		} catch (Exception e) {
			return true;
		}
	}

	/**
	 * Extracts the expiration date from a JWT token.
	 * <p>
	 * Returns the "exp" (expiration) claim as a {@link Date}. Useful for
	 * logging, audit trails, or determining when a token will expire. Does
	 * not perform expiration comparison; use {@link #isTokenExpired(String)}
	 * for that.
	 *
	 * @param token the JWT token
	 * @return the expiration date/time
	 * @throws io.jsonwebtoken.JwtException if the token is invalid
	 * @see com.maruf.auth.service.RefreshTokenStore
	 */
	public Date getExpirationDate(String token) {
		return extractAllClaims(token).getExpiration();
	}

	/**
	 * Returns the RSA public key for external verification.
	 * <p>
	 * Exposes the RSA public key so that other services (e.g., resource servers)
	 * can verify tokens without access to the private key. Typically used
	 * by JWKS endpoint to serve the key in RFC 7517 format. Allows distributed
	 * token verification while maintaining private key security.
	 *
	 * @return the RSA public key
	 * @see com.maruf.auth.config.WellKnownController
	 */
	public RSAPublicKey getPublicKey() {
		return rsaPublicKey;
	}

	/**
	 * Loads an RSA private key from a PEM file.
	 * <p>
	 * Reads a PKCS8-formatted PEM file, extracts the Base64-encoded content
	 * (removing header/footer and whitespace), decodes it, and reconstructs
	 * an {@link RSAPrivateKey} instance using {@link KeyFactory}.
	 *
	 * @param path the file path to the PEM private key
	 * @return the loaded RSA private key
	 * @throws IOException              if the file cannot be read
	 * @throws NoSuchAlgorithmException if the RSA algorithm is not available
	 * @throws InvalidKeySpecException  if the PEM content is not valid PKCS8
	 */
	private RSAPrivateKey loadPrivateKey(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String pem = Files.readString(Path.of(path));
		String base64 = pem
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replaceAll("\\s", "");
		byte[] keyBytes = Base64.getDecoder().decode(base64);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return (RSAPrivateKey) keyFactory.generatePrivate(spec);
	}

	/**
	 * Loads an RSA public key from a PEM file.
	 * <p>
	 * Reads an X509-formatted PEM file, extracts the Base64-encoded content
	 * (removing header/footer and whitespace), decodes it, and reconstructs
	 * an {@link RSAPublicKey} instance using {@link KeyFactory}.
	 *
	 * @param path the file path to the PEM public key
	 * @return the loaded RSA public key
	 * @throws IOException              if the file cannot be read
	 * @throws NoSuchAlgorithmException if the RSA algorithm is not available
	 * @throws InvalidKeySpecException  if the PEM content is not valid X509
	 */
	private RSAPublicKey loadPublicKey(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String pem = Files.readString(Path.of(path));
		String base64 = pem
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");
		byte[] keyBytes = Base64.getDecoder().decode(base64);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) keyFactory.generatePublic(spec);
	}
}
