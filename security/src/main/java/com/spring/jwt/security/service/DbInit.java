package com.spring.jwt.security.service;

import com.spring.jwt.security.entity.User;
import com.spring.jwt.security.model.Role;
import com.spring.jwt.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class DbInit implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        userRepository.deleteAll();

        User user = User.builder()
                .email("user@gmail.com")
                .password(passwordEncoder.encode("user123"))
                .role(Role.USER)
                .authorities(Role.USER.getAuthorities())
                .build();

        User admin = User.builder()
                .email("admin@gmail.com")
                .password(passwordEncoder.encode("admin123"))
                .role(Role.ADMIN)
                .authorities(Role.ADMIN.getAuthorities())
                .build();
        userRepository.saveAll(List.of(user, admin));
    }
}
