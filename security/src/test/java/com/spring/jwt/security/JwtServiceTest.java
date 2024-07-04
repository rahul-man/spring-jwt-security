package com.spring.jwt.security;

import io.jsonwebtoken.Jwts;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

public class JwtServiceTest {

    @Test
    void  generateSecretKey(){
        SecretKey secretKey = Jwts.SIG.HS512.key().build();
        String enCodedKey = DatatypeConverter.printHexBinary(secretKey.getEncoded());
        System.out.println(String.format("key %s", enCodedKey));
    }
}
