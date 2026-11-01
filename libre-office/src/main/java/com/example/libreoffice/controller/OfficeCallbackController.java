package com.example.libreoffice.controller;

import com.example.libreoffice.payload.request.OfficeCallbackRequest;
import com.example.libreoffice.payload.response.OfficeCallbackResponse;
import com.example.libreoffice.service.IOfficeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.json.JsonMapper;

/**
 * Endpoint ONLY-OFFICE gọi (server-to-server).
 * Bắt buộc trả {"error":0}; trả {"error":1} để ONLYOFFICE gửi lại.
 * Production: chỉ cho IP của ONLY-OFFICE gọi /office/**.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/office")
public class OfficeCallbackController {
    private final IOfficeService officeService;
    private final JsonMapper jsonMapper;          // bean có sẵn của Spring Boot 4

    @PostMapping("/callback/{id}")
    public ResponseEntity<OfficeCallbackResponse> callback(@PathVariable String id, @RequestBody OfficeCallbackRequest body) {
        OfficeCallbackResponse response = new OfficeCallbackResponse(officeService.handleCallback(id, body));
        return ResponseEntity.ok(response);
    }
}
