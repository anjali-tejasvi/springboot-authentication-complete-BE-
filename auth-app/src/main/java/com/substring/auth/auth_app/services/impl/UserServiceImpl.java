package com.substring.auth.auth_app.services.impl;


import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.enities.Provider;
import com.substring.auth.auth_app.enities.User;
import com.substring.auth.auth_app.exceptions.ResourceNotFoundException;
import com.substring.auth.auth_app.helpers.UserHelper;
import com.substring.auth.auth_app.repositories.UserRepository;
import com.substring.auth.auth_app.services.UserServices;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.stream.StreamSupport;

@Service
@RequiredArgsConstructor
public class UserServiceImpl  implements UserServices {

    private final UserRepository userRepository;

    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        if(userDto.getEmail() == null || userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is required");
        }

        if (userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("User with given email already exists");
        }

       User user =   modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);
        System.out.println("--create user----"+ user);

        //role assign here to user ---->  for authorization (will implement later)

        User savedUser= userRepository.save(user);

        return modelMapper.map(savedUser,UserDto.class);
    }

    @Override
    public UserDto getUserEmail(String email) {
       User user = userRepository.findByEmail(email)
               .orElseThrow(()-> new ResourceNotFoundException("user not found with given emilId"));

       return modelMapper.map(user,UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userID) {
        UUID uid =  UserHelper.parseUUID(userID);
        User existingUser =  userRepository.findById(uid).orElseThrow(()->  new ResourceNotFoundException("User not found with this ID"));

        // we are not going to change the emailId for this project
        if(userDto.getName()  != null) existingUser.setName(userDto.getName());
        if(userDto.getImage() != null) existingUser.setImage(userDto.getImage());
        if(userDto.getProvider() != null) existingUser.setProvider(userDto.getProvider());
        if(userDto.getPassword() != null) existingUser.setPassword(userDto.getPassword());
        existingUser.setEnable(userDto.isEnable());
        existingUser.setUpdatedAt(Instant.now());
        User updatedUser =  userRepository.save(existingUser);

        return modelMapper.map(updatedUser,  UserDto.class);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uid  = UserHelper.parseUUID(userId);
        User user =  userRepository.findById(uid)
                .orElseThrow(()-> new ResourceNotFoundException("User is not available with this id"));

        userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user  =
                userRepository.findById(UserHelper.parseUUID(userId))
                        .orElseThrow(()-> new ResourceNotFoundException("user not found with this id"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return StreamSupport
                .stream(userRepository.findAll().spliterator(), false)
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }
}
