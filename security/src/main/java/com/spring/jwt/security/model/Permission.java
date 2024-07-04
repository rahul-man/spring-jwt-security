package com.spring.jwt.security.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum Permission {

    USER_CREATE("user:create"),
    USER_READ("user:read"),
    USER_UPDATE("user:update"),
    USER_DELETE("user:delete"),
    ADMIN_ALL("admin:all");

    private final String permissions;
}
