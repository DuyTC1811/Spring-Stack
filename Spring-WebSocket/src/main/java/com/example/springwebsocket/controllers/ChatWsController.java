package com.example.springwebsocket.controllers;

import com.example.springwebsocket.model.WsDtos;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.MessageExceptionHandler;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.handler.annotation.support.MethodArgumentNotValidException;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.stereotype.Controller;

import java.security.Principal;
import java.time.Instant;

@Slf4j
@Controller
public class ChatWsController {
    /**
     * FE: publish('/app/chat.send', { content }) → mọi client subscribe /topic/chat
     */
    @MessageMapping("/chat.send")
    @SendTo("/topic/chat")
    public WsDtos.ChatMessage send(@Valid @Payload WsDtos.SendChatRequest req, Principal principal) {
        log.info("chat from={} content={}", principal.getName(), req.content());
        return new WsDtos.ChatMessage(principal.getName(), req.content().trim(), Instant.now());
    }

    /**
     * Gõ "/echo xin chào" → chỉ người gửi nhận lại (test /user/queue)
     */
    @MessageMapping("/chat.echo")
    @SendToUser("/queue/notifications")
    public WsDtos.NotificationMessage echo(@Payload WsDtos.SendChatRequest req) {
        return new WsDtos.NotificationMessage(java.util.UUID.randomUUID().toString(),
                WsDtos.NotificationMessage.Type.INFO, "Echo", req.content(), Instant.now());
    }

    /**
     * Payload sai (content rỗng, > 500 ký tự) → trả lỗi riêng cho người gửi
     */
    @MessageExceptionHandler(MethodArgumentNotValidException.class)
    @SendToUser("/queue/errors")
    public WsDtos.ErrorMessage onInvalid(MethodArgumentNotValidException ex) {
        return new WsDtos.ErrorMessage("VALIDATION_ERROR", "Nội dung không hợp lệ (1–500 ký tự)");
    }

    @MessageExceptionHandler(Exception.class)
    @SendToUser("/queue/errors")
    public WsDtos.ErrorMessage onError(Exception ex) {
        log.error("WS error", ex);
        return new WsDtos.ErrorMessage("INTERNAL_ERROR", ex.getMessage());
    }
}
