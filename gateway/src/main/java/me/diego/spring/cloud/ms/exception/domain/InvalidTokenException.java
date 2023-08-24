package me.diego.spring.cloud.ms.exception.domain;

import lombok.Getter;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.server.ResponseStatusException;

@Getter
public class InvalidTokenException extends ResponseStatusException {

    public InvalidTokenException(HttpStatusCode status) {
        super(status);
    }
}
