package com.maruf.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the authentication service.
 * <p>
 * This Spring Boot application acts as a standalone OAuth2 authorization server
 * and JWT issuer. It handles GitHub/Microsoft OAuth2 flows, local
 * email/password authentication, issues RS256-signed access and refresh tokens,
 * and exposes a JWKS endpoint for public key discovery.
 *
 * @see com.maruf.auth.service.JwtService
 * @see com.maruf.auth.controller.AuthController
 */
@SpringBootApplication
@EnableScheduling
public class AuthenticationApplication {

	/**
	 * Bootstrap method invoked by the JVM.
	 *
	 * @param args command line arguments (unused)
	 */
	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}
}
