package com.substring.auth.auth_app.services;

import com.substring.auth.auth_app.dtos.UserDto;

import java.util.UUID;

public interface UserServices {

        //create user
        UserDto createUser(UserDto userDto);

        //get user by email
        UserDto getUserEmail(String email);

        //update user
        UserDto updateUser(UserDto userDto, String userID);


        //delete  user
        void deleteUser(String userId);

        //get user by id
        UserDto getUserById(String userId);

        //get all users
        Iterable<UserDto> getAllUsers();

}
