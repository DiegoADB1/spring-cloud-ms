package me.diego.spring.cloud.ms;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

@SpringBootApplication(exclude = {ReactiveSecurityAutoConfiguration.class})
@EnableDiscoveryClient
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("course", r -> r
                        .path("/course/**")
                        .filters(f -> f.rewritePath("/course/(?<path>.*)", "/${path}"))
                        .uri("lb://course"))
                .route("auth", r -> r
                        .path("/auth/**")
                        .filters(f -> f.rewritePath("/auth/(?<path>.*)", "/${path}"))
                        .uri("lb://auth"))
                .build();
    }
}