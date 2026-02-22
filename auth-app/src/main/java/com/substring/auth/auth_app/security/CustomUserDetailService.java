package com.substring.auth.auth_app.security;

import com.substring.auth.auth_app.enities.User;
import com.substring.auth.auth_app.exceptions.ResourceNotFoundException;
import com.substring.auth.auth_app.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
@RequiredArgsConstructor
public class CustomUserDetailService  implements UserDetailsService {

    private  final UserRepository userRepository;



    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<User> optionalUser = userRepository.findByEmail(username);

        System.out.println("Email from request: " + username);
        System.out.println("User from DB: " + optionalUser);

        User user = optionalUser
                .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password"));

        System.out.println("Stored Password: " + user.getPassword());
        return user;
    }
}
