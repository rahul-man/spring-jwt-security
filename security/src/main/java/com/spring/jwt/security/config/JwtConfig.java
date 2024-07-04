package com.spring.jwt.security.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Configuration
@ConfigurationProperties("app.jwt")
public class JwtConfig {
    private String secretKey;
    private int expirationTimeInMinutes;
    private String type;
    private String issuer;
}
