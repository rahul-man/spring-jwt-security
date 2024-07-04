package com.spring.jwt.security.exception;

import com.spring.jwt.security.model.ApiError;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.security.sasl.AuthenticationException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ApiError> handleSignatureException(SignatureException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiError.builder()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .errorMessage("Invalid JWT Signature")
                .error(e.getMessage())
                .build());
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiError> handleExpiredJwtException(ExpiredJwtException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiError.builder()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .errorMessage("Expired JWT token")
                .error(e.getMessage())
                .build());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDeniedException(AccessDeniedException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiError.builder()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .errorMessage("You are not authorized to access this resource")
                .error(e.getMessage())
                .build());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiError> handleBadCredentialsException(BadCredentialsException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiError.builder()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .errorMessage("Incorrect username or password")
                .error(e.getMessage())
                .build());
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiError> handleAuthenticationException(AuthenticationException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiError.builder()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .errorMessage("Invalid Jwt Token")
                .error(e.getMessage())
                .build());
    }

    @ExceptionHandler(AccountStatusException.class)
    public ResponseEntity<ApiError> handleAccountStatusException(AccountStatusException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiError.builder()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .errorMessage("Account is abnormal")
                .error(e.getMessage())
                .build());
    }

    @ExceptionHandler(InsufficientAuthenticationException.class)
    public ResponseEntity<ApiError> handleInsufficientAuthenticationException(InsufficientAuthenticationException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiError.builder()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .errorMessage("Invalid Jwt Token")
                .error(e.getMessage())
                .build());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleException(Exception e) {
        return ResponseEntity.internalServerError().body(ApiError.builder()
                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .errorMessage("Something went wrong. Unknown internal server error")
                .error(e.getMessage())
                .build());
    }
}
