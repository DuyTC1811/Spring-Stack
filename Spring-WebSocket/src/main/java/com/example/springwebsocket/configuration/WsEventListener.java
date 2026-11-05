package com.example.springwebsocket.configuration;

import com.example.springwebsocket.model.WsDtos;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.messaging.SessionConnectedEvent;
import org.springframework.web.socket.messaging.SessionDisconnectEvent;

import java.security.Principal;
import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class WsEventListener {
    private final SimpMessagingTemplate template;

    @EventListener
    public void onConnected(SessionConnectedEvent e) {
        String user = name(e.getUser());
        log.info("WS CONNECTED user={}", user);
        template.convertAndSend("/topic/chat", new WsDtos.ChatMessage("system", user + " đã vào phòng", Instant.now()));
    }

    @EventListener
    public void onDisconnect(SessionDisconnectEvent e) {
        String user = name(e.getUser());
        log.info("WS DISCONNECTED user={} status={}", user, e.getCloseStatus());
        template.convertAndSend("/topic/chat", new WsDtos.ChatMessage("system", user + " đã rời phòng", Instant.now()));
    }

    private String name(Principal p) {
        return p != null ? p.getName() : "unknown";
    }
}
