package com.spring.jwt.security.config;

import com.spring.jwt.security.entity.JwtToken;
import com.spring.jwt.security.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler {

    private static final String BEARER = "Bearer ";

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isEmpty(authHeader) || !authHeader.startsWith(BEARER)) {
            log.error("Authorization header is missing or doesn't starts with Bearer");
            return;
        }
        String jwtToken = authHeader.substring(7);
        log.info("Fetching the existing token from db and Invalidate the token");
        JwtToken token = tokenRepository.findByAccessToken(jwtToken).orElse(null);
        if (token != null) {
            token.setUserLoggedOut(true);
            tokenRepository.save(token);
            log.info("Token successfully invalidated and updated");
        }
    }
}
