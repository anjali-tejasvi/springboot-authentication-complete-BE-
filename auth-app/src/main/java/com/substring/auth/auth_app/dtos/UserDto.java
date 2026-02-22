package com.substring.auth.auth_app.dtos;

import com.substring.auth.auth_app.enities.Provider;
import lombok.*;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {

    private UUID id;
    private String email;
    private String password;
    private String name;
    private String image;
    private boolean enable;
    private Instant createdAt;
    private Instant updatedAt;
    private Provider provider;
    private Set<RoleDto> roles;
}
