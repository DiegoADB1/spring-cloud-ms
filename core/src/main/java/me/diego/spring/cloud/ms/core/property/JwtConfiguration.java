package me.diego.spring.cloud.ms.core.property;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt.config")
public class JwtConfiguration {
    public static final String LOGIN_URL = "/login";
    public static final String HEADER_NAME =  "Authorization";
    public static final String HEADER_PREFIX = "Bearer ";
    public static final int EXPIRATION = 3600;
    public static final String PRIVATE_KEY = "hWgxCccjxBKg9MJ8ItdYlm9napoAnmKT";
    public static final String TYPE = "signed";
}
