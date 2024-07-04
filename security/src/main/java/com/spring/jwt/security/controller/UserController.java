package com.spring.jwt.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/home")
    public ResponseEntity<String> home() {
        return ResponseEntity.ok("Welcome to USER home");
    }
}
