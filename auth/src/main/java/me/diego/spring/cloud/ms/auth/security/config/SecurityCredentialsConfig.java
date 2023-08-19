package me.diego.spring.cloud.ms.auth.security.config;

import lombok.RequiredArgsConstructor;
import me.diego.spring.cloud.ms.auth.security.filter.JwtAuthenticationFilter;
import me.diego.spring.cloud.ms.token.security.config.SecurityTokenConfig;
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

@RequiredArgsConstructor
@EnableWebSecurity
@Import({TokenCreator.class})
@Configuration
public class SecurityCredentialsConfig extends SecurityTokenConfig{
    private final TokenCreator tokenCreator;

    @Override
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        var authManager = authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));

        http
                .addFilter(new JwtAuthenticationFilter(authManager, tokenCreator));

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
