package com.substring.auth.auth_app.exceptions;


import com.substring.auth.auth_app.dtos.ApiError;
import com.substring.auth.auth_app.dtos.ErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.logging.Logger;

@RestControllerAdvice
public class GlobalExceptionHandler {

//    private final Logger logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException exception){
       ErrorResponse internalServerError =  new ErrorResponse(exception.getMessage(), HttpStatus.NOT_FOUND);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(internalServerError);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse>  handleIllegalArgumentException(IllegalArgumentException exception){
        ErrorResponse internalServerError =  new ErrorResponse(exception.getMessage(), HttpStatus.BAD_REQUEST);
        return  ResponseEntity.status(HttpStatus.BAD_REQUEST).body(internalServerError);
    }


    @ExceptionHandler({
            UsernameNotFoundException.class,
            BadCredentialsException.class,
            CredentialsExpiredException.class,
            AuthenticationException.class,
            DisabledException.class
    })
    public ResponseEntity<ApiError> handleAuthException(Exception e, HttpServletRequest request){
//        logger.info("Exception "+ e.getClass().getName());
      ApiError apiError =  ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad request", e.getMessage(), request.getRequestURI());
        return ResponseEntity.badRequest().body(apiError);
    }

}
