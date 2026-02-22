package com.substring.auth.auth_app.services.impl;

import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.services.AuthService;
import com.substring.auth.auth_app.services.UserServices;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserServices userService;
    private  final PasswordEncoder passwordEncoder;

    @Override
    public UserDto registerUser(UserDto userDto) {

        //logic
        //verify email
        //verify password
        //default roles

        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        UserDto userDto1 =  userService.createUser(userDto);
        return userDto1;
    }
}
