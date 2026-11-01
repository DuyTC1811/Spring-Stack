package com.example.libreoffice.configuration.config;

import com.example.libreoffice.model.CurrentUser;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class FakeUserProvider {
    public static final String HEADER = "X-Fake-User";
    public static final String DEFAULT_USER = "aaf4bf6d-926c-407c-a61b-7ca03b7a54c9";
    private static final Map<String, CurrentUser> FAKE_USERS = Map.of(
            "aaf4bf6d-926c-407c-a61b-7ca03b7a54c9", new CurrentUser("aaf4bf6d-926c-407c-a61b-7ca03b7a54c9", "Nguyễn Văn A", List.of("OFFICER")),
            "26e9b4e0-a7ea-4f58-9459-4ae8ba70376a", new CurrentUser("26e9b4e0-a7ea-4f58-9459-4ae8ba70376a", "Trần Thị B", List.of("VIEWER")),
            "3e700fd6-4d58-42ea-ac32-bf1ce56efdb2", new CurrentUser("3e700fd6-4d58-42ea-ac32-bf1ce56efdb2", "Lê Văn C", List.of()));

    private static final Map<String, CurrentUser> USERS = Map.of(
            "u001", new CurrentUser("u001", "Nguyễn Văn A", List.of("FX_OFFICER")),
            "u002", new CurrentUser("u002", "Trần Thị B", List.of("FX_VIEWER")),
            "u003", new CurrentUser("u003", "Lê Văn C", List.of()));

    public CurrentUser resolve(String id) {
        return FAKE_USERS.getOrDefault(id, FAKE_USERS.get(DEFAULT_USER));
    }
}
