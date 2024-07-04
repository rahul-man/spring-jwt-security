package com.spring.jwt.security.entity;

import com.spring.jwt.security.model.Role;
import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_user")
public class User {
    @Id
    @GeneratedValue
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
    private String authorities;
    @OneToMany(mappedBy = "user")
    @ToString.Exclude
    private List<JwtToken> jwtTokens;
}
