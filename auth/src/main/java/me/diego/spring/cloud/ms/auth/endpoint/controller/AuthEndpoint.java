package me.diego.spring.cloud.ms.auth.endpoint.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.auth.security.config.JwtTokenService;
import me.diego.spring.cloud.ms.auth.endpoint.service.AuthService;
import me.diego.spring.cloud.ms.auth.security.user.dto.UserDto;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthEndpoint {

    private final AuthService authService;
    private final JwtTokenService jwtTokenService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserDto userDto) {
        Authentication authenticate = authService.login(userDto);

        String encryptToken = jwtTokenService.generateTokenJWE(authenticate);

        log.info("Token generated successfully, adding it to the response header");

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "XSRF-TOKEN, " + JwtConfiguration.HEADER_NAME);
        httpHeaders.add(JwtConfiguration.HEADER_NAME, JwtConfiguration.HEADER_PREFIX + encryptToken);

        return ResponseEntity.ok().headers(httpHeaders).build();
    }
}
