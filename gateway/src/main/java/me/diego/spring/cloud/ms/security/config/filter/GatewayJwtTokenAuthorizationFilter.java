package me.diego.spring.cloud.ms.security.config.filter;

import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import me.diego.spring.cloud.ms.token.security.token.converter.TokenConverter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Import;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import static me.diego.spring.cloud.ms.token.security.util.SecurityContextUtil.setSecurityContext;

@Component
@Slf4j
@RequiredArgsConstructor
@Import({TokenConverter.class, JwtConfiguration.class})
public class GatewayJwtTokenAuthorizationFilter implements GlobalFilter  {
    private final TokenConverter tokenConverter;

    @Override
    @SneakyThrows
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        List<String> headerList = exchange.getRequest().getHeaders().get(JwtConfiguration.HEADER_NAME);

        if (headerList == null || headerList.isEmpty()) {
            return chain.filter(exchange);
        }

        String header = headerList.get(0);

        if (!header.startsWith(JwtConfiguration.HEADER_PREFIX)) {
            return chain.filter(exchange);
        }

        String token = header.replace(JwtConfiguration.HEADER_PREFIX, "").trim();

        String signedToken = tokenConverter.decryptToken(token);

        tokenConverter.validateTokenSignature(signedToken);

        setSecurityContext(SignedJWT.parse(signedToken));

        if (JwtConfiguration.TYPE.equalsIgnoreCase("signed")) {
            ServerHttpRequest mutateRequest = exchange.getRequest()
                    .mutate()
                    .header(JwtConfiguration.HEADER_NAME, JwtConfiguration.HEADER_PREFIX + signedToken).build();

            return chain.filter(exchange.mutate().request(mutateRequest).build());
        }

        return chain.filter(exchange);
    }

}