package com.substring.auth.auth_app.services;

import com.substring.auth.auth_app.dtos.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
}
