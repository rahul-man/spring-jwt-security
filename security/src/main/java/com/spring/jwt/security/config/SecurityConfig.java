package com.spring.jwt.security.config;

import com.spring.jwt.security.filter.JwtAuthenticationFilter;
import com.spring.jwt.security.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final CustomLogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("auth/**", "/h2-console/**")
                        .permitAll()
                        .requestMatchers("/admin/**").hasRole(Role.ADMIN.name())
                        .requestMatchers("/user/**").hasRole(Role.USER.name())
                        .anyRequest()
                        .authenticated()
                )
                .exceptionHandling(e -> e.authenticationEntryPoint(authenticationEntryPoint))
                .exceptionHandling(e -> e.accessDeniedHandler(accessDeniedHandler))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                //JwtFilter has to be executed before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(l -> l
                        .logoutUrl("/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(
                                ((request, response, authentication) -> SecurityContextHolder.clearContext())
                        )
                )
                .headers(SecurityConfig::customize);
        return http.build();
    }

    //for enabling h2-console
    private static void customize(HeadersConfigurer<HttpSecurity> headersConfigurer) {
        headersConfigurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable);
    }
}
