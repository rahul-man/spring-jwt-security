package com.spring.jwt.security.service;

import com.spring.jwt.security.entity.User;
import com.spring.jwt.security.model.AppUser;
import com.spring.jwt.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findByEmail(userEmail);
        if (optionalUser.isPresent()) {
            return optionalUser.map(AppUser::new).get();
        } else {
            throw new UsernameNotFoundException(String.format("Username with %s not found", userEmail));
        }
    }
}
