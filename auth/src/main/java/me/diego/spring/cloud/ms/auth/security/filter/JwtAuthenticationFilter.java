package me.diego.spring.cloud.ms.auth.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        log.info("Attempting authentication. . .");
        String authorizationField = request.getHeader(JwtConfiguration.HEADER_NAME);

        if (authorizationField == null || !authorizationField.startsWith(JwtConfiguration.HEADER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        log.info("Creating the authentication for the user '{}' and calling UserDetailsServiceImpl loadByUsername", "fodase");

        chain.doFilter(request, response);
    }
}
