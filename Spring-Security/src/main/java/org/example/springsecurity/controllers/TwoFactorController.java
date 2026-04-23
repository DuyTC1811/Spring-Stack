package org.example.springsecurity.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.example.springsecurity.configurations.caffeine.ICacheService;
import org.example.springsecurity.configurations.jwt.JwtUtil;
import org.example.springsecurity.configurations.properties.SecurityProperties;
import org.example.springsecurity.configurations.security.UserInfo;
import org.example.springsecurity.exceptions.BaseException;
import org.example.springsecurity.handlers.ITwoFactorService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

import static org.example.springsecurity.enums.EException.OTP_IS_INCORRECT;
import static org.example.springsecurity.enums.ESensitivityLevel.CRITICAL;


@RestController
@RequiredArgsConstructor
@Tag(name = "TWO-FACTOR", description = "API 2FA")
@RequestMapping("/api/2fa")
@PreAuthorize("isAuthenticated()") // CHECK ĐÃ ĐĂNG NHẬP CHƯA
public class TwoFactorController {
    private final ITwoFactorService twoFactorService;
    private final ICacheService cacheService;
    private final JwtUtil jwtUtil;
    private final SecurityProperties securityProperties;

    private static final String KEY_PREFIX = "2fa:stepup:%s:%s";

    @Operation(summary = "Khởi tạo 2FA: trả về QR code cho user đang đăng nhập")
    @PostMapping("/setup")
    public ResponseEntity<byte[]> setup() {
        String username = currentUsername();
        byte[] qrImage = twoFactorService.beginSetup(username);
        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_PNG)
                .body(qrImage);
    }

    @Operation(summary = "Xác nhận code sau khi scan QR để kích hoạt 2FA")
    @PostMapping("/verify-setup")
    public ResponseEntity<String> confirm(@RequestBody @Valid OtpCodeReq req) {
        String username = currentUsername();
        if (!twoFactorService.confirmSetup(username, req.code())) {
            throw new BaseException(OTP_IS_INCORRECT);
        }
        return ResponseEntity.ok("Bật 2FA thành công");
    }

    @Operation(summary = "Verify OTP cho user đã bật 2FA")
    @PostMapping("/verify")
    public ResponseEntity<String> verify(@RequestBody @Valid OtpCodeReq req) {
        String username = currentUsername();
        String token = jwtUtil.tokenContext();
        String jti = jwtUtil.extractJti(token, securityProperties.getAccessSecret());

        if (!twoFactorService.verifyCode(username, req.code())) {
            throw new BaseException(OTP_IS_INCORRECT);
        }
        String key = String.format(KEY_PREFIX, username, jti);
        cacheService.putCache(key, req.code, Duration.ofMinutes(CRITICAL.getMinutes()));
        return ResponseEntity.ok("Verify Successfully");
    }

    private String currentUsername() {
        String username = jwtUtil.usernameByContext().getUsername();
        if (username.isBlank()) {
            throw new BaseException(401, "Unauthorized");
        }
        return username;
    }

    public record OtpCodeReq(@NotBlank String code) {
    }
}
