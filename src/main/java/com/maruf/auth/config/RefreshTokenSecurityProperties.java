package com.maruf.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for refresh token security behavior.
 * <p>
 * Binds properties from the application YAML file under the
 * {@code app.security.refresh-token}
 * prefix to control refresh token hashing and rotation strategies. These
 * settings are injected
 * into {@link com.maruf.auth.service.RefreshTokenStore} to determine token
 * lifecycle and
 * storage policies.
 * <p>
 * <b>Example configuration:</b>
 * 
 * <pre>
 * app:
 *   security:
 *     refresh-token:
 *       hashing-enabled: true     # Store SHA-256 hash instead of raw token
 *       rotation-enabled: true    # Issue new refresh token on each use
 * </pre>
 *
 * @author Maruf Bepary
 * @see com.maruf.auth.service.RefreshTokenStore
 * @see com.maruf.auth.config.AuthController
 */
@Component
@ConfigurationProperties(prefix = "app.security.refresh-token")
@Data
public class RefreshTokenSecurityProperties {

	/**
	 * Whether to store refresh tokens as SHA-256 hashes in PostgreSQL.
	 * <p>
	 * When enabled ({@code true}), the raw refresh token is hashed using SHA-256
	 * before storage. This prevents database compromise from directly exposing
	 * valid
	 * tokens. The plain token is only retained in the HTTP-only cookie on the
	 * client.
	 * When disabled ({@code false}), the raw token is stored (less secure but
	 * simpler
	 * to debug). Defaults to {@code true}.
	 */
	private boolean hashingEnabled = true;

	/**
	 * Whether to issue a new refresh token each time a token is
	 * validated/refreshed.
	 * <p>
	 * When enabled ({@code true}), every successful refresh operation invalidates
	 * the old refresh token and issues a new one, sent to the client in the
	 * response.
	 * This limits the lifespan of any stolen token to one use. When disabled
	 * ({@code false}),
	 * the same refresh token can be reused until its natural expiration. Defaults
	 * to {@code true}.
	 */
	private boolean rotationEnabled = true;
}
