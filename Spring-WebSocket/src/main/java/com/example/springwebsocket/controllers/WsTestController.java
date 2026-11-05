package com.example.springwebsocket.controllers;

import com.example.springwebsocket.model.WsDtos;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.user.SimpUser;
import org.springframework.messaging.simp.user.SimpUserRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/ws-test")
@RequiredArgsConstructor
public class WsTestController {
    private final SimpMessagingTemplate template;
    private final SimpUserRegistry userRegistry;

    /** Danh sách user đang online */
    @GetMapping("/online")
    public List<String> online() {
        return userRegistry.getUsers().stream().map(SimpUser::getName).sorted().toList();
    }

    /** Gửi notification riêng cho 1 user → /user/queue/notifications */
    @PostMapping("/notify/{username}")
    public ResponseEntity<WsDtos.NotificationMessage> notify(@PathVariable String username,
                                                             @Valid @RequestBody WsDtos.NotifyRequest req) {
        if (userRegistry.getUser(username) == null) {
            return ResponseEntity.notFound().build();
        }
        var msg = new WsDtos.NotificationMessage(UUID.randomUUID().toString(),
                req.type() != null ? req.type() : WsDtos.NotificationMessage.Type.INFO,
                req.title(), req.body(), Instant.now());
        template.convertAndSendToUser(username, "/queue/notifications", msg);
        return ResponseEntity.ok(msg);
    }

    /** Server broadcast vào phòng chat → /topic/chat */
    @PostMapping("/broadcast")
    public WsDtos.ChatMessage broadcast(@RequestParam String content) {
        var msg = new WsDtos.ChatMessage("server", content, Instant.now());
        template.convertAndSend("/topic/chat", msg);
        return msg;
    }

}
