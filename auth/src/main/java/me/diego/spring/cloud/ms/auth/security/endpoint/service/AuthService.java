package me.diego.spring.cloud.ms.auth.security.endpoint.service;

import lombok.RequiredArgsConstructor;
import me.diego.spring.cloud.ms.auth.security.user.dto.UserDto;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;

    public Authentication login(UserDto userDto) {
        UserDetails user = userDetailsService.loadUserByUsername(userDto.username());
        Authentication authenticate;
        try {
            authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userDto.username(), userDto.password(), user.getAuthorities()));
        } catch (BadCredentialsException exc) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Username or password are incorrect");
        }

        SecurityContextHolder.getContext().setAuthentication(authenticate);

        return authenticate;
    }
}
