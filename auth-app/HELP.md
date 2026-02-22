# 🔐 Spring Boot | Spring Security authentication | Complete BE

A production-ready **stateless authentication system** built with Spring Boot, Spring Security, and JWT.
Implements secure login, short-lived access tokens, refresh token rotation, and HttpOnly cookie delivery — **without OAuth**.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [How It Works](#-how-it-works)
    - [Authentication Flow](#authentication-flow)
    - [Token Strategy](#token-strategy)
    - [Why Cookies for the Refresh Token?](#why-cookies-for-the-refresh-token)
    - [Refresh Token Rotation](#refresh-token-rotation)
- [Security Design Decisions](#-security-design-decisions)
- [Configuration & Environments](#-configuration--environments)
    - [How Spring Profiles Work](#how-spring-profiles-work)
    - [application.yml — Shared Base](#applicationyml--shared-base)
    - [application-dev.yml](#application-devyml)
    - [application-qa.yml](#application-qayml)
    - [application-prod.yml](#application-prodyml)
- [Running the Project](#-running-the-project)
- [Production Checklist](#-production-checklist)
- [Not Implemented](#-not-implemented)

---

## ✅ Features

- User registration and login with Spring Security `AuthenticationManager`
- JWT-based **stateless** authentication — no server-side sessions
- Short-lived **access tokens** sent in the response body
- Long-lived **refresh tokens** persisted in DB + delivered via `HttpOnly` cookie
- **Refresh token rotation** — every `/refresh` call issues a new token and revokes the old one
- Refresh token revocation and expiry enforcement
- Multi-source refresh token reading: cookie → body → `X-Refresh-Token` header → `Authorization: Bearer`
- Structured logging (`log.info`, `log.warn`, `log.debug`) — no sensitive values ever logged
- Multi-environment config: `dev`, `qa`, `prod` Spring profiles
- Secrets loaded from local `.env.local` file (never committed to Git)

---

## 🛠 Tech Stack

| Layer | Technology                       |
|---|----------------------------------|
| Language | Java 17+                         |
| Framework | Spring Boot 3                    |
| Security | Spring Security 6                |
| JWT | JJWT / Nimbus (via `JwtService`) |
| ORM | Spring Data JPA / Hibernate      |
| Database | MySQL 8                          |
| Connection Pool | HikariCP                         |
| Mapping | ModelMapper                      |
| Boilerplate | Lombok                           |

---

## 🔄 How It Works

### Authentication Flow

```
Client                              Server
  │                                   │
  │  POST /api/v1/auth/login          │
  │  { email, password }  ───────────►│
  │                                   │  1. AuthenticationManager validates credentials
  │                                   │  2. Load user from DB, check isEnabled()
  │                                   │  3. Generate JTI (UUID), persist RefreshToken to DB
  │                                   │  4. Sign Access Token  (JWT, short TTL)
  │                                   │  5. Sign Refresh Token (JWT, long TTL + JTI claim)
  │                                   │  6. Set HttpOnly cookie with Refresh Token
  │                                   │  7. Set Cache-Control: no-store
  │◄──────────────────────────────────│
  │  200 OK                           │
  │  { accessToken, expiresIn, user } │
  │  Set-Cookie: refreshToken=...     │
```

---

### Token Strategy

Two tokens are issued on every successful login or token refresh:

#### Access Token
- Signed JWT containing `userId`, `email`, roles, `iat`, `exp`
- **Short-lived** — 1 hour in dev/qa, 15 minutes in prod
- Sent in the **response body** — client holds it in memory (never `localStorage`)
- Attached to every API request as `Authorization: Bearer <accessToken>`
- **Stateless** — never stored server-side; validated purely by signature + expiry

#### Refresh Token
- Signed JWT containing `userId` and a `jti` (UUID — the database key)
- **Long-lived** — 24 hours in dev/qa, 7 days in prod
- A `RefreshToken` record is **persisted in the database** keyed by `jti`
- Delivered to the client only via an **HttpOnly cookie**
- Only accepted at `POST /api/v1/auth/refresh`

---

### Why Cookies for the Refresh Token?

Refresh tokens are long-lived and high-value. Storing them incorrectly is a critical security mistake.

**Why NOT `localStorage` or `sessionStorage`?**
Any JavaScript running on your page — including injected scripts, compromised npm packages, or browser extensions — can call `localStorage.getItem('refreshToken')`. This is a **Cross-Site Scripting (XSS)** vulnerability. Once stolen, the attacker can silently mint new access tokens for the full lifetime of the refresh token.

**Why HttpOnly cookies?**
An `HttpOnly` cookie is **completely invisible to JavaScript**. The browser holds it and sends it automatically on matching requests, but no script — yours or an attacker's — can ever read its value.

```
┌──────────────────────────────────────────────────────────────┐
│  Cookie flags in this project                                │
│                                                              │
│  HttpOnly   → JS cannot read it              (XSS guard)    │
│  Secure     → HTTPS only                     (MitM guard)   │
│  SameSite   → Blocks cross-site POST         (CSRF guard)   │
│  Domain     → .substring.com (all subdomains)               │
│  Path       → /api/v1/auth  (scoped, not global)            │
└──────────────────────────────────────────────────────────────┘
```

**Why keep access tokens in memory and not in a cookie too?**
Short TTL limits exposure. Memory storage means the token disappears on tab close — intentional. The browser silently calls `/refresh` with the cookie and the client gets a new access token seamlessly. Best balance of security and UX.

---

### Refresh Token Rotation

Every `/refresh` call **immediately revokes the old token** and issues a brand new one.

```
Client                                       Server
  │                                             │
  │  POST /api/v1/auth/refresh                  │
  │  Cookie: refreshToken=<oldJWT>  ───────────►│
  │                                             │  1. Parse JWT → extract JTI + userId
  │                                             │  2. Look up RefreshToken by JTI in DB
  │                                             │  3. Validate: not revoked, not expired,
  │                                             │               userId matches JWT claim
  │                                             │  4. Mark old token revoked=true
  │                                             │     Store replacedByToken = newJTI
  │                                             │  5. Persist new RefreshToken (new JTI)
  │                                             │  6. Issue new Access Token + Refresh Token
  │                                             │  7. Set new HttpOnly cookie
  │◄────────────────────────────────────────────│
  │  200 OK                                     │
  │  { newAccessToken, expiresIn, user }        │
  │  Set-Cookie: refreshToken=<newJWT>          │
```

**Why rotate?**
If a refresh token is stolen, both the attacker and the real user will try to use it. Whichever one goes first causes the other's attempt to hit a **revoked token**. At that point the server knows a token was reused — and can revoke the entire family by following the `replacedByToken` chain.

---

## 📡 API Endpoints

Base path: `http://localhost:8083/api/v1/auth` (dev)

---

### `POST /register`

**Request Body:**
```json
{
  "email": "anjali@example.com",
  "password": "yourpassword",
  "name": "anjali",
  "image": "https://cdn.example.com/images/john.png",
  "enable": true
}

```

**Response:** `201 Created`
```json
{
  "id": "23f874af-b467-4910-8ab5-4295d3176cc8",
  "email": "anjali@example.com",
  "name": "anjali",
  "image": "https://cdn.example.com/images/john.png",
  "enable": true,
  "createdAt": "2026-02-19T05:22:13.101827900Z",
  "updatedAt": "2026-02-19T05:22:13.101827900Z",
  "provider": "LOCAL",
  "roles": null
}
```

---

### `POST /login`

**Request Body:**
```json
{
  "email": "anjali@example.com",
  "password": "yourpassword"
}
```

**Response:** `200 OK`
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiIzOTM4ZTdkOC0wZWQwLTQwZDItYWJjNy1iNTkxNjMyZTJhZmUiLCJzdWIiOiIyM2Y4NzRhZi1iNDY3LTQ5MTAtOGFiNS00Mjk1ZDMxNzZjYzgiLCJpc3MiOiJhcGkuc3Vic3RyaW5nLmNvbSIsImlhdCI6MTc3MTY4MTkzOCwiZXhwIjoxNzcxNjg1NTM4LCJlbWFpbCI6ImFuamFsaUBleGFtcGxlLmNvbSIsInJvbGVzIjpbXSwidHlwIjoiYWNjZXNzIn0.hbllyLVIJPEyHgSp29q6TXdMrjVUyzAu_p2l-6g-RIHTEWHv9aBW_nAbB2MMXDrFJY5L-UKM8ZTQD3ZyzxVChw",
  "refreshToken": "eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiI4MTViOWJiZS0xN2VhLTQwOGYtOTgxZC03OWM0YmVkYzE5YjQiLCJzdWIiOiIyM2Y4NzRhZi1iNDY3LTQ5MTAtOGFiNS00Mjk1ZDMxNzZjYzgiLCJpc3MiOiJhcGkuc3Vic3RyaW5nLmNvbSIsImlhdCI6MTc3MTY4MTkzOCwiZXhwIjoxNzcxNzY4MzM4LCJ0eXAiOiJyZWZyZXNoIn0.kNoCZ5S3jFay5-4b0jXctClrBoIaDYS0eVGhfz4manaHmjBiOEcz-NA667ZWo7obWyHoYKe-2KFKBMAB-O8vfA",
  "expiresIn": 3600,
  "tokenType": "Bearer",
  "user": {
    "id": "23f874af-b467-4910-8ab5-4295d3176cc8",
    "email": "anjali@example.com",
    "name": "anjali",
    "image": "https://cdn.example.com/images/john.png",
    "enable": true,
    "createdAt": "2026-02-19T05:22:13.101828Z",
    "updatedAt": "2026-02-19T05:22:13.101828Z",
    "provider": "LOCAL",
    "roles": []
  }
}
```

**Response Headers set by server:**
```
Set-Cookie: refreshToken=<jwt>; HttpOnly; Secure; SameSite=Lax; Domain=.substring.com
Cache-Control: no-store
```

---

### `POST /refresh`

No body needed when using the cookie. The server reads the refresh token from these sources **in priority order**:

| Priority | Source |
|---|---|
| 1  | `HttpOnly` cookie named `refreshToken` (preferred) |
| 2 | Request body `{ "refreshToken": "..." }` |
| 3 | Custom header `X-Refresh-Token: <token>` |
| 4 | `Authorization: Bearer <token>` (only if token type claim is `refresh`) |

**Response:** `200 OK` — same shape as `/login`. New tokens issued, old refresh token revoked.

---

## 🔒 Security Design Decisions

| Decision | Why |
|---|---|
| Refresh token stored in DB | Enables server-side revocation — a pure JWT cannot be invalidated before expiry |
| JTI claim on refresh token | Links the JWT to one DB row; prevents replay of identical tokens |
| `HttpOnly` cookie for refresh token | JS-invisible — survives XSS attacks that would steal `localStorage` |
| Access token in response body (not cookie) | Avoids CSRF risk; short TTL limits exposure if intercepted |
| `Cache-Control: no-store` on auth responses | Prevents browsers and CDN proxies from caching responses that contain tokens |
| `isEnabled()` check on login | Allows soft-disabling accounts without deletion |
| Token type claim validation on `/refresh` | Prevents an access token being submitted as a refresh token |
| `userId` cross-check on refresh | Ensures the cookie token actually belongs to the user it claims to represent |
| `replacedByToken` chain on rotation | Enables full token family revocation on detected reuse |

---

## ⚙️ Configuration & Environments

### How Spring Profiles Work

Spring Boot merges config files in this order — later files override earlier ones:

```
application.yml                ← always loaded (shared base, no secrets)
       +
application-{profile}.yml     ← loaded when that profile is active
       +
Environment variables          ← highest priority (secrets injected here)
```

Activate a profile:
```bash
# Maven (local dev)
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev

# JAR (server / CI)
java -jar app.jar --spring.profiles.active=prod

# Environment variable
export SPRING_PROFILES_ACTIVE=qa
```

---





### `application.yml` — Shared Base

Loaded in **every** environment. Contains shared structure only — no ports, no DB URLs, no credentials.

```yaml
# application.yml
spring:
  application:
    name: auth-app

  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    hikari:
      pool-name: AuthAppHikariPool
      auto-commit: true

  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQL8Dialect

security:
  jwt:
    secret: ${SECURITY_JWT_SECRET}       # always injected — never hardcoded here
    issuer: api.substring.com
    refresh-token-cookie-name: refreshToken
    cookie-http-only: true
```

---

### `application-dev.yml`

Activated with `--spring.profiles.active=dev`. Verbose logging, relaxed cookie rules (HTTP is fine locally), auto DDL. Port `8083`.

```yaml
# application-dev.yml
server:
  port: 8083

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/auth_app
    username: ${SPRING_DATASOURCE_USERNAME:root}   # fallback to root if env var missing
    password: ${SPRING_DATASOURCE_PASSWORD:root}
    hikari:
      minimum-idle: 2
      maximum-pool-size: 5
      idle-timeout: 30000
      connection-timeout: 30000
      max-lifetime: 1800000

  jpa:
    hibernate:
      ddl-auto: update       # auto-migrate schema — fine for dev
    show-sql: true           # log all SQL queries to console

logging:
  level:
    org.springframework.security: DEBUG
    com.yourapp: DEBUG

security:
  jwt:
    access-ttl-seconds: 3600       # 1 hour — long enough to develop without re-login
    refresh-ttl-seconds: 86400     # 24 hours
    cookie-secure: false           # allow HTTP in local dev (no TLS locally)
    cookie-same-site: lax
    cookie-domain: localhost
```

> `${SPRING_DATASOURCE_USERNAME:root}` — uses the env var if present, otherwise falls back to `root`.  
> Zero-config startup for new developers, overridable for custom setups.

---

### `application-qa.yml`

Activated with `--spring.profiles.active=qa`. Mirrors production behaviour but points to QA infrastructure. Secrets injected by CI/CD pipeline.

```yaml
# application-qa.yml
server:
  port: 8080

spring:
  datasource:
    url: jdbc:mysql://qa-db.internal:3306/auth_app_qa
    username: ${SPRING_DATASOURCE_USERNAME}     # must be set by CI/CD — no fallback
    password: ${SPRING_DATASOURCE_PASSWORD}
    hikari:
      minimum-idle: 3
      maximum-pool-size: 10
      idle-timeout: 30000
      connection-timeout: 30000
      max-lifetime: 1800000

  jpa:
    hibernate:
      ddl-auto: validate     # fail fast if schema doesn't match entities
    show-sql: false

logging:
  level:
    org.springframework.security: INFO
    com.yourapp: INFO

security:
  jwt:
    access-ttl-seconds: 3600
    refresh-ttl-seconds: 86400
    cookie-secure: true
    cookie-same-site: lax
    cookie-domain: .qa.substring.com
```

---

### `application-prod.yml`

Activated with `--spring.profiles.active=prod`. Hardened settings. No DDL, no SQL logging, strict cookie policy, shorter access token TTL.

```yaml
# application-prod.yml
server:
  port: 8080

spring:
  datasource:
    url: jdbc:mysql://${DB_HOST}:3306/${DB_NAME}
    username: ${SPRING_DATASOURCE_USERNAME}
    password: ${SPRING_DATASOURCE_PASSWORD}
    hikari:
      minimum-idle: 5
      maximum-pool-size: 20
      idle-timeout: 30000
      connection-timeout: 30000
      max-lifetime: 1800000

  jpa:
    hibernate:
      ddl-auto: none         # NEVER auto-migrate in prod — use Flyway or Liquibase
    show-sql: false

logging:
  level:
    org.springframework.security: WARN
    com.yourapp: INFO
    root: WARN

security:
  jwt:
    access-ttl-seconds: 900        # 15 minutes — tighter window in prod
    refresh-ttl-seconds: 604800    # 7 days
    cookie-secure: true
    cookie-same-site: strict       # strictest CSRF protection — no cross-site sending at all
    cookie-domain: .substring.com
```

---

### `.env.local` — Dev Secrets (Git-ignored)

Create this file on your local machine. **Do not commit it — ever.**

```bash
# Step 1: copy the example
cp .env.local.example .env.local

# Step 2: generate a real secret
openssl rand -base64 32

# Step 3: paste into .env.local
```

```bash
# .env.local  (your machine only — git-ignored)
SECURITY_JWT_SECRET=<output of openssl rand -base64 32>
SPRING_DATASOURCE_USERNAME=root
SPRING_DATASOURCE_PASSWORD=root
```

---


## 🚀 Running the Project

### Prerequisites

- Java 17+
- MySQL 8 running locally
- Maven 3.8+

### First-Time Setup

```bash
# 1. Clone
git clone https://github.com/your-username/auth-app.git
cd auth-app

# 2. Create the local database
mysql -u root -p -e "CREATE DATABASE auth_app;"

# 3. Set up your local secrets
cp .env.local.example .env.local
# Open .env.local and fill in your values
# Generate a JWT secret: openssl rand -base64 32

# 4. Run with dev profile
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

The API is now available at: `http://localhost:8083/api/v1/auth`

### Running Other Profiles

```bash
# QA profile
./mvnw spring-boot:run -Dspring-boot.run.profiles=qa

# Build and run as a JAR (production)
./mvnw clean package -DskipTests
java -jar target/auth-app.jar --spring.profiles.active=prod
```

swagger 
```http://localhost:8083/swagger-ui/index.html```
---

## 🚧 Not Implemented

Intentionally excluded from this backend:

- **OAuth2 / Social Login** — no Google, GitHub, or any identity provider
- **Email verification** — users are active immediately after registration
- **Password reset** — no forgot-password or email-based reset flow
- **Rate limiting** — no brute-force login protection
- **Schema migrations** — no Flyway or Liquibase integration

---

## 📚 Key Concepts Reference

| Term | Meaning |
|---|---|
| JWT | JSON Web Token — a signed, self-contained token encoding claims |
| JTI | JWT ID — a unique `jti` claim inside a JWT, used here as the DB lookup key |
| Access Token | Short-lived JWT for authenticating API requests |
| Refresh Token | Long-lived JWT for obtaining new access tokens; persisted in DB |
| Token Rotation | Every `/refresh` issues a new refresh token and revokes the previous one |
| HttpOnly Cookie | Browser cookie that JavaScript cannot read — primary XSS defence |
| Stateless Auth | Server stores no session; all auth info is in the signed JWT |
| Token Revocation | Server-side invalidation of a token before its natural expiry via DB flag |
| JTI Chain | `replacedByToken` links on `RefreshToken` rows — enables family revocation on reuse |
| Spring Profile | Environment-specific config file activated via `spring.profiles.active` |