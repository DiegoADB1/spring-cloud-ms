package me.diego.spring.cloud.ms.course;

import me.diego.spring.cloud.ms.core.docs.BaseSwaggerConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan({"me.diego.spring.cloud.ms.core.domain"})
@EnableJpaRepositories({"me.diego.spring.cloud.ms.core.repository"})
@Import(BaseSwaggerConfig.class)
@EnableDiscoveryClient
public class CourseApplication {

	public static void main(String[] args) {
		SpringApplication.run(CourseApplication.class, args);
	}

}
