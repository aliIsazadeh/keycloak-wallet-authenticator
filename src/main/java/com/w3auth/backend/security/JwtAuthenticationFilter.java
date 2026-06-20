package com.w3auth.backend.security;

import com.w3auth.backend.session.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.util.Collections;

/**
 * Reads the {@code Authorization: Bearer <token>} header, validates the access JWT
 * via {@link JwtService}, and sets Spring's {@code SecurityContext} for the duration
 * of the request.
 *
 * <p>Fail-closed: any problem with the token (bad signature, expired, malformed,
 * wrong audience) clears the context and lets the chain continue unauthenticated.
 * The downstream security config rejects unauthenticated requests with 401.
 *
 * <p>Not annotated {@code @Component} — registered as a bean in
 * {@code infrastructure.JwtConfiguration} and wired into the security filter chain
 * via {@link SecurityConfiguration}. This avoids Spring Boot's servlet auto-registration,
 * which would execute the filter twice per request.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final Clock clock;

    public JwtAuthenticationFilter(JwtService jwtService, Clock clock) {
        this.jwtService = jwtService;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.substring(BEARER_PREFIX.length());
        try {
            Claims claims = jwtService.parse(token, clock.instant());
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            claims.getSubject(), null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (JwtException e) {
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}
