package me.diego.spring.cloud.ms.token.security.filter;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.core.property.JwtConfiguration;
import me.diego.spring.cloud.ms.token.security.token.converter.TokenConverter;
import me.diego.spring.cloud.ms.token.security.util.SecurityContextUtil;
import org.apache.commons.lang.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtTokenAuthorizationFilter extends OncePerRequestFilter {
    protected final TokenConverter tokenConverter;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(JwtConfiguration.HEADER_NAME);

        if (header == null || !header.startsWith(JwtConfiguration.HEADER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.replace(JwtConfiguration.HEADER_PREFIX, "").trim();

        SignedJWT validatedToken = StringUtils.equalsIgnoreCase("signed", JwtConfiguration.TYPE) ? validate(token) : decryptValidating(token);

        SecurityContextUtil.setSecurityContext(validatedToken);

        chain.doFilter(request, response);
    }

    @SneakyThrows
    private SignedJWT decryptValidating(String encryptedToken) {
        String signedToken = tokenConverter.decryptToken(encryptedToken);

        tokenConverter.validateTokenSignature(signedToken);

        return SignedJWT.parse(signedToken);
    }

    @SneakyThrows
    private SignedJWT validate(String signedToken) {
        tokenConverter.validateTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }
}
