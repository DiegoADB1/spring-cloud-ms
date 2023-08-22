package me.diego.spring.cloud.ms.security.config.filter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.RequiredArgsConstructor;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import me.diego.spring.cloud.ms.token.security.token.converter.TokenConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class GatewayAuthorizationFilter implements WebFilter {
    private final TokenConverter tokenConverter;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
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

        JWTClaimsSet claims = getClaims(signedToken);

        ArrayList<String> authorities = (ArrayList<String>) claims.getClaim("authorities");
        List<SimpleGrantedAuthority> authoritiesParsed = parseRoles(authorities);
        String username = claims.getSubject();

        var authentication = new UsernamePasswordAuthenticationToken(username, null, authoritiesParsed);

        return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }

    private JWTClaimsSet getClaims(String signedToken) {
        JWTClaimsSet claims;
        try {
            claims = SignedJWT.parse(signedToken).getJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException(e.getMessage());
        }

        return claims;
    }

    private List<SimpleGrantedAuthority> parseRoles(List<String> roles) {
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }
}
