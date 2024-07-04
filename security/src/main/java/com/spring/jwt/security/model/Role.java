package com.spring.jwt.security.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.spring.jwt.security.model.Permission.ADMIN_ALL;
import static com.spring.jwt.security.model.Permission.USER_CREATE;
import static com.spring.jwt.security.model.Permission.USER_DELETE;
import static com.spring.jwt.security.model.Permission.USER_READ;
import static com.spring.jwt.security.model.Permission.USER_UPDATE;


@Getter
@AllArgsConstructor
public enum Role {

    USER(Set.of(USER_CREATE, USER_READ, USER_UPDATE, USER_DELETE)),

    ADMIN(Set.of(ADMIN_ALL));

    private final Set<Permission> authorities;

    public Set<SimpleGrantedAuthority> grantedAuthorities() {
        Set<SimpleGrantedAuthority> authoritySet = this.authorities.stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermissions()))
                .collect(Collectors.toSet());
        authoritySet.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authoritySet;
    }

    public String getAuthorities() {
        return authorities.stream()
                .map(Permission::getPermissions)
                .collect(Collectors.joining(", "));
    }
}
