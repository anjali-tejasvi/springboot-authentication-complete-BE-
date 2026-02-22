package com.substring.auth.auth_app.controllers;

import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.services.UserServices;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private  final UserServices userService;

    @PostMapping
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto){
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(userService.createUser(userDto));
    }

    @GetMapping
    public ResponseEntity<Iterable<UserDto>> getAllUsers() {
        return ResponseEntity
                .ok(userService.getAllUsers());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String email){
        return  ResponseEntity.ok(userService.getUserEmail(email));
    }

    //get user by userId
    @GetMapping("{userId}")
    public ResponseEntity<UserDto> getUserBYId(@PathVariable String userId){
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    //delete user
    @DeleteMapping("/{userId}")
    public void deleteUser(@PathVariable("userId") String userId){
        userService.deleteUser(userId);
    }


    //update user
    @PutMapping("/{userId}")
    public  ResponseEntity<UserDto>  updateUser(@RequestBody UserDto userDto,  @PathVariable("userId") String userId){
        return ResponseEntity.ok(userService.updateUser(userDto,userId));
    }



}
