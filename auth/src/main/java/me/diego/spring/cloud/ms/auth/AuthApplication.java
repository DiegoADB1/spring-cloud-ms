package me.diego.spring.cloud.ms.auth;

import me.diego.spring.cloud.ms.core.docs.BaseSwaggerConfig;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableDiscoveryClient
@EnableConfigurationProperties(value = JwtConfiguration.class)
@EntityScan({"me.diego.spring.cloud.ms.core.domain"})
@EnableJpaRepositories({"me.diego.spring.cloud.ms.core.repository"})
@Import(BaseSwaggerConfig.class)
public class AuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}