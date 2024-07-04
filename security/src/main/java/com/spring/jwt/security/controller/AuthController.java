package com.spring.jwt.security.controller;

import com.spring.jwt.security.model.LoginRequest;
import com.spring.jwt.security.model.LoginResponse;
import com.spring.jwt.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/token")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginRequest loginRequest) {
        LoginResponse response = authenticationService.authenticate(loginRequest);
        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, response.getToken())
                .body(response);
    }

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@RequestBody LoginRequest loginRequest) {
        LoginResponse loginResponse = authenticationService.register(loginRequest);
        return ResponseEntity.ok(loginResponse);
    }
}
