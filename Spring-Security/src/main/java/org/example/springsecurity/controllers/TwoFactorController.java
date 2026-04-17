package org.example.springsecurity.controllers;

import lombok.RequiredArgsConstructor;
import org.example.springsecurity.exceptions.BaseException;
import org.example.springsecurity.handlers.ITwoFactorService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.example.springsecurity.enums.EException.OTP_IS_INCORRECT;
import static org.example.springsecurity.utils.TOTPUtil.generateSecret;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/2fa")
public class TwoFactorController {
    private final ITwoFactorService twoFactorService;

    @PostMapping("/setup/{username}")
    public byte[] setup(@PathVariable String username) {

        String issuer = "MySpringApp";
//        String otpAuthUrl = twoFactorService.buildOtpAuthUrl(secret, username, issuer);

        return twoFactorService.generateQrCode(generateSecret(), username, issuer);
    }

    @PostMapping("/enable")
    public ResponseEntity<byte[]> enable2FA() {
        byte[] qrImage = twoFactorService.generateQrCode(generateSecret(), "noname", "DEM_APP");
        return ResponseEntity.status(201)
                .contentType(MediaType.IMAGE_PNG)
                .body(qrImage);
    }

    @PostMapping("/verify-setup")
    public String confirm(@RequestBody Enable2FAReq req) {
        Enable2FAReq req1 = new Enable2FAReq(null);
//        UserEntity user = userRepository.findById(username)
//                .orElseThrow(() -> new RuntimeException("Không tìm thấy user"));

        boolean valid = twoFactorService.verifyCode("asdfasdf", req1.code);
        if (!valid) {
            throw new BaseException(OTP_IS_INCORRECT);
        }
        return "Bật 2FA thành công";
    }

    record Enable2FAReq(String code) {
    }
}
