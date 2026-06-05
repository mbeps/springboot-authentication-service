# **Spring Boot OAuth 2.0 Identity Provider**

A standalone OAuth 2.0 and Local Authentication Service built with Spring Boot 4.0.3. This service provides secure identity management, multi-provider OAuth2 flows, and RS256-signed JWT issuance for consumption by any compliant frontend or backend service. It features a JWKS endpoint for seamless public key distribution, enabling resource servers to verify user identity without shared secrets.

The application implements a dual-token authentication system with short-lived access tokens and long-lived refresh tokens, both intended to be stored as httpOnly cookies to prevent XSS attacks. The service owns all identity logic—OAuth2 flows, RS256 JWT signing with an RSA private key, and PostgreSQL storage for token lifecycle management. Resource servers remain completely independent, verifying JWTs via the JWKS public key endpoint.

# Features

## Authentication and Authorisation
The application provides comprehensive OAuth 2.0 authentication with flexible provider support:
- **Dynamic OAuth Provider Support**: GitHub and/or Microsoft Entra ID (Azure AD) with runtime selection
- Providers are dynamically discovered from configuration and exposed via `/api/auth/providers` endpoint
- **Email/Password Authentication**: Optional local authentication that can be enabled/disabled via configuration
- Provider-agnostic authentication with Spring Security OAuth2 Client
- Users can log out securely with complete token invalidation
- Automatic token refresh maintains session continuity

## JWT Token Management
Secure token generation, validation, and lifecycle management with RS256 asymmetric signing:
- **RS256 RSA asymmetric signing**: The service signs tokens with an RSA private key; external applications and resource servers verify tokens using the public key fetched from the JWKS endpoint
- Only this service can sign valid tokens (holds the RSA private key); resource servers are decoupled from signing logic
- Dual-token system with access tokens (15 minutes by default) and refresh tokens (7 days by default)
- Automatic token generation upon successful authentication
- Token validation on protected endpoints
- Custom JWT claims with user information (ID, username, email, avatar) and token type identifier
- Token expiry handling and validation
- Automatic access token refresh using refresh tokens
- Refresh token rotation for enhanced security
- Persistent refresh token storage in PostgreSQL

## Multi-Service Integration
Designed to serve as a central Identity Provider (IdP) for multiple client applications and resource servers:
- **JWKS Endpoint**: RFC 7517 compliant JSON Web Key Set for automated public key distribution
- **Standardised JWTs**: Issued tokens can be consumed by any OIDC-compliant or JWT-compatible resource server
- **Dynamic Redirect URI**: Securely validates and redirects to multiple whitelisted application origins

## Token Invalidation and Session Management
Secure session termination and cleanup:
- Access token invalidation on logout (blacklist storage)
- Refresh token revocation from database
- Automatic cleanup of expired tokens via scheduled background task

## User Profile Management
Hydrates user profile information across providers:
- Normalised OAuth provider profile details (GitHub or Microsoft)
- User avatar and username resolution
- User ID and email information retrieval

## Public Endpoints
Discovery endpoints for monitoring and integration:
- Public health check endpoint
- Authentication status verification
- Provider discovery endpoint
- JWKS public key endpoint

# Requirements
These are the requirements needed to run the service:
- Java 21 or higher
- PostgreSQL 14 or higher
- OAuth Application credentials for one or both providers (configured in `application.yaml`):
  - **GitHub OAuth Application** (Client ID and Client Secret)
  - **Microsoft Entra ID App Registration** (Client ID, Client Secret, and Tenant ID)

# Stack
These are the main technologies used in this project:

## Auth Service
- [**Java**](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html): An object-oriented programming language with strong typing and extensive libraries.
- [**Spring Boot**](https://spring.io/projects/spring-boot): A framework for building production-ready applications with minimal configuration. This project uses Spring Boot 4.0.3 with updated starters: `spring-boot-starter-webmvc` and `spring-boot-starter-security-oauth2-client`.
- [**Spring Security**](https://spring.io/projects/spring-security): Comprehensive security framework providing authentication and authorisation.
- [**Spring Security OAuth2 Client**](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html): OAuth 2.0 client implementation for handling provider callbacks and authorization.
- [**Spring Data JPA**](https://spring.io/projects/spring-data-jpa): Provides integration with PostgreSQL for token persistence and user storage.
- [**JJWT**](https://github.com/jwtk/jjwt): Java JWT library for creating and parsing JSON Web Tokens with RS256 RSA signing.
- [**Gradle**](https://gradle.org/): Build automation tool for dependency management and project building.

## Database
- [**PostgreSQL**](https://www.postgresql.org/): Relational database for storing refresh tokens, users, and invalidated access tokens with scheduled cleanup of expired entries.

# Design

## Token Storage Strategy
The service issues tokens intended for `httpOnly` cookie storage by client applications. This approach prevents XSS attacks as JavaScript cannot access these cookies. Access tokens have a 15-minute lifespan whilst refresh tokens last 7 days by default. 

## Database Architecture
PostgreSQL is used for persistence by the service. It stores three tables:

- `users`: Local user credentials and profile information (used when local auth is enabled)
  - `id`: UUID
  - `email`: Unique login identifier
  - `password`: BCrypt hash
  - `name`: Display name
  - `avatarUrl`: Optional profile picture URL
  - `roles`: User roles (e.g. ROLE_USER)

- `refresh_tokens`: Long-lived tokens supporting rotation and hashing
  - `id`: UUID
  - `token`: SHA-256 hash of the token (when hashing is enabled)
  - `username`: Associated user email/login
  - `expiresAt`: Expiry timestamp; column used by scheduled cleanup task to remove expired entries
  - `createdAt`: Token creation timestamp
  - `lastUsed`: Timestamp of last refresh use

- `invalidated_access_tokens`: Blacklist of revoked but not yet naturally expired access tokens
  - `id`: UUID
  - `token`: Raw JWT string (unique indexed)
  - `username`: User identifier for audit
  - `expiresAt`: Token's natural expiry; removed by scheduled cleanup task at expiry
  - `invalidatedAt`: Logout/revocation timestamp
  - `reason`: Reason for invalidation (e.g. "logout")

All tables use a scheduled background cleanup task to automatically delete expired entries.

## JWT Token Structure & RS256 Signing
Access tokens contain user claims (ID, login, name, email, avatar URL) and a type field set to `access`. Refresh tokens contain minimal information with type set to `refresh`. 

**Signing**: Tokens are signed using **RS256 RSA asymmetric signing**:
- The service signs tokens with an RSA private key loaded from `keys/auth-private.pem` (PKCS8 PEM format)
- External resource servers verify tokens using the RSA public key fetched from the service's `/.well-known/jwks.json` JWKS endpoint (RFC 7517)
- This asymmetric approach ensures that only the identity provider can create valid tokens; resource servers cannot forge tokens even if compromised
- Key rotation requires only service redeployment; consumers re-fetch the JWKS key naturally

## Multi-Service Support
The system is architected as a central Identity Provider for multiple consumers. Identification is handled through stateful origin validation:

### CORS Origin Validation
Requests are validated against the `auth.allowed-origins` list. Each consuming origin (frontends or other services) must be whitelisted. This prevents unauthorised services from accessing auth endpoints.

### OAuth2 Redirect URI Validation
When initiating an OAuth2 flow, the `CustomOAuth2AuthorizationRequestResolver` validates the `redirect_uri` query parameter against the `auth.allowed-redirect-urls` whitelist. This enables a single service instance to support multiple client domains safely.

### How Services Are Identified
Services are identified by their origin URL. The provider requires **no per-service credentials** for internal API validation—origin-based validation is the primary security boundary. To add a new consumer:
1. Add its origin to `auth.allowed-origins`
2. Add its redirect base URL to `auth.allowed-redirect-urls`

### Configuration Example
```yaml
auth:
  allowed-origins:
    - https://app1.example.com
    - https://app2.example.com
  allowed-redirect-urls:
    - https://app1.example.com/callback
    - https://app2.example.com/callback
```

## Authentication flow
The service (port 8081) handles all identity operations:

1. User initiates login via a client application
2. Client redirects to the **auth service** (port 8081) with a `redirect_uri` parameter
3. Service validates the `redirect_uri` and encodes it into the OAuth2 state
4. Service redirects to the OAuth provider (GitHub/Azure); user approves
5. Provider redirects back to service: `/login/oauth2/code/{registrationId}`
6. Success handler generates **RS256-signed JWTs**, stores the refresh token, sets `httpOnly` cookies, and redirects the browser back to the original `redirect_uri`
7. Resource servers verify subsequent requests using the public key fetched from the JWKS endpoint

## Logout Flow
The logout flow revokes both tokens:

1. Client application calls `POST /logout` on the **auth service**
2. Service adds the access token to the `invalidated_access_tokens` table
3. Service deletes the refresh token from PostgreSQL
4. Service clears cookies and returns success

# Setting Up Project
These are the steps to run the service locally.

## 1. Clone the Project Locally
```sh
git clone https://github.com/mbeps/oauth-springboot-auth-service.git
cd oauth-springboot-auth-service
```

## 2. Set Up PostgreSQL
Ensure PostgreSQL is running locally (default: `jdbc:postgresql://localhost:5433/auth_db_pg`). The service will automatically create the required tables and schema via Hibernate.

## 3. Create OAuth Applications
Configure your OAuth providers in `application.yaml`:

### GitHub OAuth Application
- **Homepage URL**: `http://localhost:8081`
- **Authorisation callback URL**: `http://localhost:8081/login/oauth2/code/github`

### Microsoft Entra ID App Registration
- **Redirect URI (SPA)**: `http://localhost:8081/login/oauth2/code/azure`
- **Scopes**: `openid`, `profile`, `email`, `offline_access`, `User.Read`
- **Authentication**: Enable PKCE and implicit flow for SPA

## 4. Configure Service
Create or update `application.yaml` with your credentials:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
          azure:
            client-id: ${AZURE_CLIENT_ID}
            client-secret: ${AZURE_CLIENT_SECRET}
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5433/auth_db_pg}
    username: ${DB_USERNAME:postgres}
    password: ${DB_PASSWORD:postgres}
    driver-class-name: org.postgresql.Driver
  jpa:
    hibernate:
      ddl-auto: update
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect

server:
  port: 8081

jwt:
  private-key-path: keys/auth-private.pem
  public-key-path: keys/auth-public.pem

auth:
  allowed-origins:
    - https://your-app.com
  allowed-redirect-urls:
    - https://your-app.com
```

### Environment Variables

```env
GITHUB_CLIENT_ID=your_id
GITHUB_CLIENT_SECRET=your_secret
AZURE_CLIENT_ID=your_id
AZURE_CLIENT_SECRET=your_secret
AZURE_TENANT_ID=your_tenant
DB_URL=jdbc:postgresql://localhost:5433/auth_db_pg
DB_USERNAME=postgres
DB_PASSWORD=postgres
JWT_PRIVATE_KEY_PATH=keys/auth-private.pem
JWT_PUBLIC_KEY_PATH=keys/auth-public.pem
AUTH_ALLOWED_ORIGIN_1=https://your-app.com
AUTH_ALLOWED_REDIRECT_1=https://your-app.com
```

## 5. Build and Run
```sh
./gradlew build
./gradlew bootRun
```

The service will be available on `http://localhost:8081`. Consumers can verify tokens via `http://localhost:8081/.well-known/jwks.json`.

# Docker Support
Run with Docker Compose:
```sh
docker compose up --build
```
Ensure you have generated the RSA key pair in the `keys/` directory first.


**For Production**:
- Generate RSA key pair: `openssl genpkey -algorithm RSA -out keys/auth-private.pem && openssl rsa -in keys/auth-private.pem -pubout -out keys/auth-public.pem`
- Set `COOKIE_SECURE=true` and `COOKIE_SAME_SITE=Strict` for HTTPS-only cookies
- Set `AUTH_ALLOWED_ORIGIN_1` and `AUTH_ALLOWED_REDIRECT_1` to your production domain(s)
- Configure PostgreSQL with authentication and SSL/TLS in `DB_URL`
- Ensure Java 21+ and Spring Boot 4.0.3 compatible dependencies

# References

## Spring Boot & Spring Security
- [Spring Boot Documentation](https://spring.io/projects/spring-boot) - Official Spring Boot framework documentation and guides for building production-grade applications.
- [Spring Security Reference](https://spring.io/projects/spring-security) - Comprehensive authentication and authorisation framework for Java applications.
- [Spring Security OAuth2 Client](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html) - OAuth2 client implementation for delegated access and provider integration.
- [Spring Data JPA](https://spring.io/projects/spring-data-jpa) - Data access layer abstraction with Spring Boot integration for PostgreSQL.

## JWT & Cryptography
- [JJWT Library](https://github.com/jwtk/jjwt) - Java JWT library supporting RS256 RSA asymmetric signing and token lifecycle management.
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) - Standard specification for JWT structure, claims, and validation.
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517) - Specification for JWKS endpoints and public key distribution format.
- [RS256 RSA Signature Algorithm](https://tools.ietf.org/html/rfc7518#section-3.3) - RSASSA-PKCS1-v1_5 using SHA-256 asymmetric signing details.
- [OpenSSL RSA Key Generation](https://www.openssl.org/docs/man3.0/man1/openssl-genpkey.html) - Command-line documentation for generating RSA key pairs in PEM format.

## OAuth2 & OpenID Connect
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) - Core OAuth2 specification defining authorization code flow and token exchange.
- [RFC 6234 - US Secure Hash and HMAC Algorithms](https://tools.ietf.org/html/rfc6234) - SHA-256 hashing algorithm used for refresh token storage.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) - Identity layer on top of OAuth2 enabling standardised user information exchange.
- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps) - GitHub's OAuth2 provider integration guide and scopes reference.
- [Microsoft Entra ID OAuth2](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) - Azure AD (Entra) OAuth2 authorization code flow documentation.

## Database & Persistence
- [PostgreSQL Documentation](https://www.postgresql.org/docs/) - Official PostgreSQL reference for SQL operations and administration.
- [Spring Data JPA Repository](https://spring.io/projects/spring-data-jpa) - Query derivation and repository pattern for RDBMS.

## Security Best Practices
- [OWASP - Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) - HttpOnly cookie vulnerability prevention and XSS attack mitigation.
- [OWASP - Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) - CSRF protection design in stateless APIs.
- [OWASP - Secure Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) - BCrypt hashing and password security guidelines.
- [SameSite Cookie Attribute](https://tools.ietf.org/html/draft-west-first-party-cookies) - Cross-site request cookie control and attack mitigation.

## Testing & Development
- [JUnit 5 Documentation](https://junit.org/junit5/docs/current/user-guide/) - Java testing framework for unit and integration tests.
- [Testcontainers](https://www.testcontainers.org/) - Docker-based test dependency management for isolated PostgreSQL testing.
- [Mockito Testing Framework](https://javadoc.io/doc/org.mockito/mockito-core/latest/org/mockito/Mockito.html) - Mocking library for Java unit tests.
- [Spring Boot Testing Guide](https://spring.io/guides/gs/testing-web/) - MockMvc and integration testing patterns for Spring Boot applications.

## Supporting Libraries
- [Lombok Project](https://projectlombok.org/) - Java annotation processor for boilerplate reduction (`@Data`, `@RequiredArgsConstructor`).
- [Jakarta Bean Validation](https://jakarta.ee/specifications/bean-validation/) - Standard validation annotations for request payload and entity constraints.
- [SLF4J & Logback](https://www.slf4j.org/) - Logging abstraction and configuration for production diagnostics.
