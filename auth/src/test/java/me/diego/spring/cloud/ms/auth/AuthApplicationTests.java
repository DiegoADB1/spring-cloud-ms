package me.diego.spring.cloud.ms.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class AuthApplicationTests {
    @Test
    void test() {
        System.out.println(new BCryptPasswordEncoder().encode("devdojo"));
    }
    //$2a$10$rgyO5R8MaX9mq7ibzeaIdugNz7.TTe3NBXepSBaVYb8QMXNpBHtn.
}
