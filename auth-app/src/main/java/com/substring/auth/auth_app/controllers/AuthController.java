package com.substring.auth.auth_app.controllers;


import com.substring.auth.auth_app.dtos.LonginRequest;
import com.substring.auth.auth_app.dtos.RefreshTokenRequest;
import com.substring.auth.auth_app.dtos.TokenResponse;
import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.enities.RefreshToken;
import com.substring.auth.auth_app.enities.User;
import com.substring.auth.auth_app.repositories.RefreshTokenRepository;
import com.substring.auth.auth_app.repositories.UserRepository;
import com.substring.auth.auth_app.security.CookieService;
import com.substring.auth.auth_app.security.JwtService;
import com.substring.auth.auth_app.services.AuthService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LonginRequest longinRequest, HttpServletResponse response) {
        log.info("Login attempt for email: {}", longinRequest.email());

        Authentication authentication = authenticate(longinRequest);

        User user = userRepository.findByEmail(longinRequest.email())
                .orElseThrow(() -> {
                    log.warn("Login failed - user not found for email: {}", longinRequest.email());
                    return new BadCredentialsException("Invalid username or password");
                });

        if (!user.isEnable()) {
            log.warn("Login failed - account is disabled for email: {}", longinRequest.email());
            throw new DisabledException("user is disabled");
        }

        String jti = UUID.randomUUID().toString();
        log.debug("Generated JTI for refresh token: {}", jti);

        var refreshTokenObj = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenObj);
        log.debug("Refresh token persisted for userId: {}", user.getId());

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenObj.getJti());

        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeader(response);

        log.info("Login successful for email: {}, userId: {}", longinRequest.email(), user.getId());

        TokenResponse tokenResponse = TokenResponse.of(accessToken, refreshToken,
                jwtService.getAccessTtlSeconds(), modelMapper.map(user, UserDto.class));
        return ResponseEntity.ok(tokenResponse);
    }

    private Authentication authenticate(LonginRequest longinRequest) {
        try {
            log.debug("Authenticating credentials for email: {}", longinRequest.email());
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(longinRequest.email(), longinRequest.password()));
        } catch (Exception e) {
            log.warn("Authentication failed for email: {} - reason: {}", longinRequest.email(), e.getMessage());
            throw new BadCredentialsException("Invalid credentials authController");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity refreshToken(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response,
            HttpServletRequest request) {

        log.info("Token refresh request received"+ body);
        String refreshToken = readRefreshTokenFromRequest(body, request)
                .orElseThrow(() -> {
                    log.warn("Token refresh failed - refresh token is missing");
                    return new BadCredentialsException("Refresh token is missing");
                });

        if (!jwtService.isRefreshToken(refreshToken)) {
            log.warn("Token refresh failed - invalid token type provided");
            throw new BadCredentialsException("Invalid token type");
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userID = jwtService.getUserId(refreshToken);
        log.info("Refresh token JTI: {}, userId: {}", jti, userID);

        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> {
                    log.warn("Token refresh failed - no stored token found for JTI: {}", jti);
                    return new BadCredentialsException("Invalid refresh token");
                });

        if (storedRefreshToken.isRevoked()) {
            log.warn("Token refresh failed - token is revoked for JTI: {}, userId: {}", jti, userID);
            throw new BadCredentialsException("Refresh token is expired or revoked");
        }

        if (storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Token refresh failed - token expired for JTI: {}, userId: {}", jti, userID);
            throw new BadCredentialsException("refresh token expired");
        }

        if (!storedRefreshToken.getUser().getId().equals(userID)) {
            log.warn("Token refresh failed - token userId mismatch. Token userId: {}, claimed userId: {}",
                    storedRefreshToken.getUser().getId(), userID);
            throw new BadCredentialsException("refresh token does not belong to this user");
        }

        // Rotate refresh token
        storedRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(storedRefreshToken);
        log.info("Old refresh token revoked. JTI: {}, replacedBy: {}", jti, newJti);

        User user = storedRefreshToken.getUser();
        var newRefreshTokenOb = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(newRefreshTokenOb);
        log.info("New refresh token persisted with JTI: {} for userId: {}", newJti, user.getId());

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user, newRefreshTokenOb.getJti());

        cookieService.attachRefreshCookie(response, newRefreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeader(response);

        log.info("Token refresh successful for userId: {}", user.getId());

        return ResponseEntity.ok(TokenResponse.of(newAccessToken, newRefreshToken,
                jwtService.getAccessTtlSeconds(), modelMapper.map(user, UserDto.class)));
    }

    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        if (request.getCookies() != null) {
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();
            if (fromCookie.isPresent()) {
                log.debug("Refresh token read from cookie");
                return fromCookie;
            }
        }

        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            log.debug("Refresh token read from request body");
            return Optional.of(body.refreshToken());
        }

        String refreshHeader = request.getHeader("X-Refresh-Token");
        if (refreshHeader != null && !refreshHeader.isBlank()) {
            log.debug("Refresh token read from X-Refresh-Token header");
            return Optional.of(refreshHeader.trim());
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer", 0, 7)) {
            String token = authHeader.substring(7).trim();
            if (!token.isBlank()) {
                try {
                    if (jwtService.isRefreshToken(token)) {
                        log.debug("Refresh token read from Authorization Bearer header");
                        return Optional.of(token);
                    }
                } catch (Exception e) {
                    log.warn("Failed to parse token from Authorization header: {}", e.getMessage());
                }
            }
        }

        log.debug("No refresh token found in any source (cookie, body, header)");
        return Optional.empty();
    }


    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response){
        readRefreshTokenFromRequest(null, request).ifPresent(token->{
            try {
                if(jwtService.isRefreshToken(token)){
                    String jti = jwtService.getJti(token);
                    refreshTokenRepository.findByJti(jti).ifPresent(rt->{
                        rt.setRevoked(true);
                        refreshTokenRepository.save(rt);
                    });
                }
            }
            catch (JwtException ignored){

            }
        });

        //Use CookieUtil (same behavior)
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/register")
    public ResponseEntity registerUser(@RequestBody UserDto userDto) {
        log.info("Registration request received for email: {}", userDto.getEmail());
        ResponseEntity response = ResponseEntity.status(HttpStatus.CREATED)
                .body(authService.registerUser(userDto));
        log.info("User registered successfully for email: {}", userDto.getEmail());
        return response;
    }
}