package me.diego.spring.cloud.ms.token.security.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.core.domain.ApplicationUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

@Slf4j
public class SecurityContextUtil {
    private SecurityContextUtil() {

    }

    public static void setSecurityContext(SignedJWT signedJWT) {
        try {
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            String username = claims.getSubject();

            if (username == null )
                throw new JOSEException("Username missing from JWT");

            List<String> authorities = claims.getStringListClaim("authorities");

            ApplicationUser applicationUser = ApplicationUser.builder()
                    .id(claims.getLongClaim("userId"))
                    .username(username)
                    .role(String.join(",", authorities))
                    .build();

            var authUser = new UsernamePasswordAuthenticationToken(applicationUser, null, createAuthorities(authorities));
            authUser.setDetails(signedJWT.serialize());
            SecurityContextHolder.getContext().setAuthentication(authUser);
        } catch (Exception e) {
            log.error("Error setting security context", e);
            SecurityContextHolder.clearContext();
        }
    }

    private static List<SimpleGrantedAuthority> createAuthorities(List<String> authorities) {
        return authorities
                .stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }
}
