package me.diego.spring.cloud.ms.auth.security.config;

import lombok.RequiredArgsConstructor;
import me.diego.spring.cloud.ms.auth.security.filter.JwtAuthenticationFilter;
import me.diego.spring.cloud.ms.token.security.config.SecurityTokenConfig;
import me.diego.spring.cloud.ms.token.security.token.converter.TokenConverter;
import me.diego.spring.cloud.ms.token.security.filter.JwtTokenAuthorizationFilter;
import me.diego.spring.cloud.ms.token.security.token.creator.TokenCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Import({TokenCreator.class, TokenConverter.class})
@Configuration
public class SecurityCredentialsConfig extends SecurityTokenConfig {
    private final TokenCreator tokenCreator;
    private final TokenConverter tokenConverter;

    @Override
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        var authManager = authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));

        http
                .addFilter(new JwtAuthenticationFilter(authManager, tokenCreator))
                .addFilterAfter(new JwtTokenAuthorizationFilter(tokenConverter), UsernamePasswordAuthenticationFilter.class);

        return super.securityFilterChain(http);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            final AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
