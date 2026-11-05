package com.example.springwebsocket.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.security.Principal;
import java.time.Instant;

public class WsDtos {
    private WsDtos() {
    }

    public record SendChatRequest(@NotBlank @Size(max = 500) String content) {
    }

    public record ChatMessage(String sender, String content, Instant timestamp) {
    }

    public record NotificationMessage(String id, Type type, String title, String body, Instant createdAt) {
        public enum Type {INFO, WARNING, ERROR}
    }

    public record NotifyRequest(NotificationMessage.Type type, @NotBlank String title, @NotBlank String body) {
    }

    public record ErrorMessage(String code, String message) {
    }

    /**
     * Principal đơn giản để Spring map /user/{name}/queue/...
     */
    public record StompPrincipal(String name) implements Principal {
        @Override
        public String getName() {
            return name;
        }
    }
}
