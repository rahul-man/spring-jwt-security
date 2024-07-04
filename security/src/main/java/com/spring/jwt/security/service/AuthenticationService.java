package com.spring.jwt.security.service;

import com.spring.jwt.security.entity.JwtToken;
import com.spring.jwt.security.entity.User;
import com.spring.jwt.security.model.AppUser;
import com.spring.jwt.security.model.LoginRequest;
import com.spring.jwt.security.model.LoginResponse;
import com.spring.jwt.security.repository.TokenRepository;
import com.spring.jwt.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AppUserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public LoginResponse authenticate(LoginRequest request) {
        LoginResponse loginResponse = null;
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        if (authentication.isAuthenticated()) {
            log.info("User {} is authenticated. Fetching user details from db", request.getEmail());
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
            if (Objects.nonNull(userDetails)) {
                Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
                List<String> authoritiesList = authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();
                log.info("Generating Jwt token for user {} with scopes {}", request.getEmail(), authoritiesList);
                AppUser appUser = (AppUser) userDetails;
                String token = jwtService.generateToken(userDetails.getUsername(), authoritiesList);
                Date expiration = jwtService.getExpiration(token);
                revokeAndSaveNewToken(appUser, token);
                log.info("Jwt token is expiring at: {}", expiration);
                loginResponse = LoginResponse.builder()
                        .token(token)
                        .expiration(expiration.toInstant().toEpochMilli())
                        .build();
            } else {
                log.error("User details not found. Invalid credentials!");
                throw new UsernameNotFoundException("Invalid Credentials!");
            }
        }
        return loginResponse;
    }

    private void revokeAndSaveNewToken(AppUser appUser, String token) {
        List<JwtToken> allAccessTokenByUser = tokenRepository.findAllAccessTokenByUser(appUser.getUser().getId());
        if (!CollectionUtils.isEmpty(allAccessTokenByUser)) {
            allAccessTokenByUser.forEach(jwtToken -> jwtToken.setUserLoggedOut(true));
        }
        JwtToken jwtToken = JwtToken.builder()
                .accessToken(token)
                .isUserLoggedOut(false)
                .user(appUser.getUser())
                .build();
        tokenRepository.save(jwtToken);
    }

    public LoginResponse register(LoginRequest loginRequest) {
        if (userRepository.findByEmail(loginRequest.getEmail()).isPresent()) {
            return new LoginResponse(null, null, "User already exists!");
        }
        User user = createAndSaveUser(loginRequest);
        String token = jwtService.generateToken(user.getEmail(), user.getRole().getAuthorities());
        Date expiration = jwtService.getExpiration(token);
        return LoginResponse.builder()
                .token(token)
                .expiration(expiration.toInstant().toEpochMilli())
                .build();
    }

    private User createAndSaveUser(LoginRequest loginRequest) {
        User user = User.builder()
                .email(loginRequest.getEmail())
                .password(passwordEncoder.encode(loginRequest.getPassword()))
                .firstname(loginRequest.getFirstName())
                .lastname(loginRequest.getLastname())
                .role(loginRequest.getRole())
                .authorities(loginRequest.getRole().getAuthorities())
                .build();
        userRepository.save(user);
        return user;
    }
}
