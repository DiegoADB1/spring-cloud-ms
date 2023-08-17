package me.diego.spring.cloud.ms.auth;

import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
@Log4j2
class AuthApplicationTests {
    @Test
    void test() {
        log.info(new BCryptPasswordEncoder().encode("devdojo"));
    }
    //$2a$10$rgyO5R8MaX9mq7ibzeaIdugNz7.TTe3NBXepSBaVYb8QMXNpBHtn.
}
