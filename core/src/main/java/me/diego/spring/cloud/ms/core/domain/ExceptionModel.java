package me.diego.spring.cloud.ms.core.domain;

public record ExceptionModel(Integer status, String message, String timestamp) {
}
