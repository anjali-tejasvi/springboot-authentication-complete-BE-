package com.substring.auth.auth_app.dtos;

import org.springframework.http.HttpStatus;

public record ErrorResponse(String message, HttpStatus status) {

}
