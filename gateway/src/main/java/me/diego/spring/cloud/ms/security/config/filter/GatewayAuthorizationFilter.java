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
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.core.domain.ApplicationUser;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import me.diego.spring.cloud.ms.token.security.token.converter.TokenConverter;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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
@Slf4j
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

        Authentication auth = createAuthentication(signedToken);

        return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
    }

    private Authentication createAuthentication(String signedToken) {
        try {
            JWTClaimsSet claims = getClaims(signedToken);
            List<String> authorities = claims.getStringListClaim("authorities");
            String username = claims.getSubject();

            ApplicationUser applicationUser = ApplicationUser.builder()
                    .id(claims.getLongClaim("userId"))
                    .username(username)
                    .role(String.join(",", authorities))
                    .build();

            var auth = new UsernamePasswordAuthenticationToken(applicationUser, null, parseRoles(authorities));
            auth.setDetails(signedToken);
            return auth;
        } catch (ParseException e) {
            log.error("Error setting security context", e);
            throw new org.apache.http.ParseException("Error while parsing jwt");
        }
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
