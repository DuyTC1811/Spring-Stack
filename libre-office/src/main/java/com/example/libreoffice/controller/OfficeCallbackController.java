package com.example.libreoffice.controller;

import com.example.libreoffice.payload.request.OfficeCallback;
import com.example.libreoffice.service.IOfficeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Endpoint ONLYOFFICE gọi (server-to-server).
 * Bắt buộc trả {"error":0}; trả {"error":1} để ONLYOFFICE gửi lại.
 * Production: chỉ cho IP của ONLYOFFICE gọi /office/**.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/office")
public class OfficeCallbackController {
    private final IOfficeService officeService;

    @PostMapping("/callback/{id}")
    public ResponseEntity<Map<String, Integer>> callback(@PathVariable String id, @RequestBody OfficeCallback body) {
        Map<String, Integer> error = Map.of("error", officeService.handleCallback(id, body));
        return ResponseEntity.ok(error);
    }
}
