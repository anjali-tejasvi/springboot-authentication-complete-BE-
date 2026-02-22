package com.substring.auth.auth_app.config;

import com.substring.auth.auth_app.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(Customizer.withDefaults());
        http.sessionManagement(sm-> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

            http
                    .authorizeHttpRequests(authorizeHttpRequests ->
                authorizeHttpRequests.requestMatchers(AppConstants.AUTH_PUBLIC_URLS).permitAll()
                .anyRequest().authenticated()
                )
                    //added after jwtAuthenticationFilter.java

                    // this will run when an unauthenticated person will try to access the resource -> this exception will generate
                    .exceptionHandling(ex ->  ex.authenticationEntryPoint((request, response, authException) -> {
                        authException.printStackTrace();
                        response.setStatus(401);
                        response.setContentType("application/json");
                        String message =  "Unauthorized access " + authException.getMessage();


                        String error = (String) request.getAttribute("error");
                        if(error !=null){
                            message = error;
                        }

                        Map<String,String> errorMap =  Map.of("message", message,"status",String.valueOf(401), "error","Unauthorized");
                        var objectMapper =  new ObjectMapper();
                        response.getWriter().write(objectMapper.writeValueAsString(errorMap));
                    }))
                    .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

                    // remove this basic as we are using jwt authentication now
//                .httpBasic(Customizer.withDefaults());
        return  http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws RuntimeException{
        return configuration.getAuthenticationManager();
    }


//    @Bean
//    public UserDetailsService users(){
//        User.UserBuilder users = User.withDefaultPasswordEncoder();
//
//        UserDetails user1 = users
//                .username("ankit")
//                .password("abc")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user2 = users
//                .username("shiva")
//                .password("abc")
//                .roles("ADMIN")
//                .build();
//
//        return  new InMemoryUserDetailsManager(user1,user2);


}
