package me.diego.spring.cloud.ms.core.docs;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition
@Configuration
public class BaseSwaggerConfig {

    @Bean
    public OpenAPI api() {
        return new OpenAPI()
                .info(metaData());
    }

    private Info metaData() {
        Contact contact = new Contact()
                .name("diego")
                .email("diego@example.com")
                .url("https://diego.com");

        License mitLicense = new License()
                .name("MIT License")
                .url("https://choosealicense.com/licenses/mit/");

        return new Info()
                .title("Spring boot microservices")
                .description("microservices")
                .version("1.0")
                .contact(contact)
                .license(mitLicense);
    }
}
