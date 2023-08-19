package me.diego.spring.cloud.ms.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.auth.security.user.dto.UserDto;
import me.diego.spring.cloud.ms.core.domain.ExceptionModel;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import me.diego.spring.cloud.ms.token.security.token.creator.TokenCreator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authRequest = getAuthRequest(request);
        Authentication authenticate;

        try {
            authenticate = authenticationManager.authenticate(authRequest);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Username or password are wrong");
        }
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        return authenticate;
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        logger.info("Authentication failed");

        var exceptionResponse = new ExceptionModel(
                HttpStatus.UNAUTHORIZED.value(),
                exception.getMessage(),
                ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'X")));

        ObjectMapper mapper = new ObjectMapper();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(mapper.writeValueAsString(exceptionResponse));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
        log.info("Authentication was successful for the user '{}', generating JWE token", auth.getName());

        String encryptToken = tokenCreator.generateTokenJWE(auth);

        log.info("Token generated successfully, adding it to the response header");

        response.addHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "XSRF-TOKEN, " + JwtConfiguration.HEADER_NAME);
        response.addHeader(JwtConfiguration.HEADER_NAME, JwtConfiguration.HEADER_PREFIX + encryptToken);
    }

    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        UserDto user = mapper.readValue(request.getInputStream(), UserDto.class);

        return new UsernamePasswordAuthenticationToken(user.username(), user.password());
    }
}
