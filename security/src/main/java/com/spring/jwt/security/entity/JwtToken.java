package com.spring.jwt.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(columnDefinition = "TEXT")
    private String accessToken;
    private boolean isUserLoggedOut;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
