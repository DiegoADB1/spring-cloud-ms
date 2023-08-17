package me.diego.spring.cloud.ms.core.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt.config")
@Getter
@Setter
@ToString
public class JwtConfiguration {
    private String loginUrl = "/login/**";
    @NestedConfigurationProperty
    private Header header = new Header();
    private int expiration = 3600;
    private String privateKey = "hWgxCccjxBKg9MJ8ItdYlm9napoAnmKT";
    private String type = "encrypted";

    @Getter
    public static class Header {
        private static final String NAME = "Authorization";
        private static final String PREFIX = "Bearer ";
    }
}
