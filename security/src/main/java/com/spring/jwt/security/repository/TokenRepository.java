package com.spring.jwt.security.repository;

import com.spring.jwt.security.entity.JwtToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<JwtToken, Integer> {

    @Query("select t from JwtToken t inner join User u " +
            "on t.user.id = u.id " +
            "where t.user.id = :userId and t.isUserLoggedOut = false")
    List<JwtToken> findAllAccessTokenByUser(Integer userId);

    Optional<JwtToken> findByAccessToken(String token);
}
