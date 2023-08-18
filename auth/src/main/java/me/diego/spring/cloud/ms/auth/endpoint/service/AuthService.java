package me.diego.spring.cloud.ms.auth.endpoint.service;

import lombok.RequiredArgsConstructor;
import me.diego.spring.cloud.ms.auth.security.user.dto.UserDto;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;

    public Authentication login(UserDto userDto) {
        Authentication authenticate;

        var authReq = new UsernamePasswordAuthenticationToken(userDto.username(), userDto.password());
        try {
            authenticate = authenticationManager.authenticate(authReq);
        } catch (BadCredentialsException exc) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username or password are incorrect");
        }

        SecurityContextHolder.getContext().setAuthentication(authenticate);

        return authenticate;
    }
}
