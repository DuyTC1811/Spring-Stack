package org.example.springsecurity.handlers.impl;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.lang3.StringUtils;
import org.example.springsecurity.configurations.caffeine.ICacheService;
import org.example.springsecurity.exceptions.BaseException;
import org.example.springsecurity.handlers.ITwoFactorService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.example.springsecurity.utils.TOTPUtil.generateSecret;
import static org.example.springsecurity.utils.TOTPUtil.verifyTotp;


@Service
@RequiredArgsConstructor
public class TwoFactorServiceImpl implements ITwoFactorService {

    private static final String PENDING_PREFIX = "2fa:pending:";
    private static final String ENABLED_PREFIX = "2fa:enabled:";
    private static final int TOTP_WINDOW = 1;

    private final ICacheService cacheService;
    private final AuthenticationHandlerImpl authenticationHandler;

    @Value("${app.two-factor.issuer:MySpringApp}")
    private String issuer;

    @Override
    public byte[] beginSetup(String username) {
        String secret = generateSecret();
        cacheService.putCache(PENDING_PREFIX + username, secret, Duration.ofMinutes(5));
        return generateQrCode(secret, username);
    }

    @Override
    public boolean confirmSetup(String username, String code) {
        String secret = cacheService.getCache(PENDING_PREFIX + username);
        if (StringUtils.isBlank(secret)) {
            throw new BaseException(400, "Phiên thiết lập 2FA đã hết hạn, vui lòng thử lại");
        }
        if (!verifyDecoded(secret, code)) {
            return false;
        }
        authenticationHandler.updateTwoFaSecret(username, secret, true);
        return true;
    }

    @Override
    public boolean verifyCode(String username, String code) {
        String secret = cacheService.getCache(ENABLED_PREFIX + username);
        if (StringUtils.isBlank(code)) {
            return false;
        }
        return verifyDecoded(secret, code);
    }

    private boolean verifyDecoded(String base32Secret, String code) {
        byte[] secretBytes = new Base32().decode(base32Secret);
        return verifyTotp(secretBytes, code, TOTP_WINDOW);
    }

    private byte[] generateQrCode(String secret, String username) {
        String otpAuth = String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                URLEncoder.encode(username, StandardCharsets.UTF_8),
                secret,
                URLEncoder.encode(issuer, StandardCharsets.UTF_8)
        );
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(otpAuth, BarcodeFormat.QR_CODE, 300, 300);
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
                return outputStream.toByteArray();
            }
        } catch (WriterException | IOException e) {
            throw new BaseException(500, "Không thể tạo QR code cho 2FA");
        }
    }
}
