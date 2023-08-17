package me.diego.spring.cloud.ms.auth.security.user.dto;

import jakarta.validation.constraints.NotNull;

public record UserDto(@NotNull(message = "Username cannot be null") String username,
                      @NotNull(message = "Password cannot be null") String password) {
}
