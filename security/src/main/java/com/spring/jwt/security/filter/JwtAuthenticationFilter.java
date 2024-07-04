package com.spring.jwt.security.filter;

import com.spring.jwt.security.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final HandlerExceptionResolver exceptionResolver;

    private static final String BEARER = "Bearer ";

    public JwtAuthenticationFilter(JwtService jwtService,
                                   UserDetailsService userDetailsService,
                                   @Qualifier("handlerExceptionResolver")
                                   HandlerExceptionResolver exceptionResolver) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        log.info("Extracting Authorization header");
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isEmpty(authHeader) || !authHeader.startsWith(BEARER)) {
            log.error("Authorization header is missing or doesn't starts with Bearer");
            filterChain.doFilter(request, response);
            return;
        }
        try {
            String jwtToken = authHeader.substring(7);
            String subject = jwtService.getSubject(jwtToken);
            if (!StringUtils.isEmpty(subject) && SecurityContextHolder.getContext().getAuthentication() == null) {
                log.info("Performing authentication checks for user: {}", subject);
                UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
                if (!jwtService.isValidToken(jwtToken, userDetails.getUsername())) {
                    log.error("Jwt validation failed. Invalid Jwt token: {}", jwtToken);
                    filterChain.doFilter(request, response);
                    return;
                } else {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    log.info("Authentication is completed for user: {}", subject);
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("Exception {} occurred while performing authentication checks: ", e.getMessage());
            exceptionResolver.resolveException(request, response, null, e);
        }
    }
}
