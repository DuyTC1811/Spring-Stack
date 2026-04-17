package org.example.springsecurity.handlers.impl;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.apache.commons.codec.binary.Base32;
import org.example.springsecurity.enums.HmacAlgorithm;
import org.example.springsecurity.handlers.ITwoFactorService;

import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.example.springsecurity.utils.TOTPUtil.verifyTotp;


@Service
public class TwoFactorServiceImpl implements ITwoFactorService {

    @Override
    public boolean verifyCode(String secret, String code) {
        byte[] secretBytes = new Base32().decode(secret);
        return verifyTotp(secretBytes, code, 6);
    }

    @Override
    public byte[] generateQrCode(String secret, String username, String issuer) {
        try {
            String otpAuth = String.format(
                    "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                    URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                    URLEncoder.encode(username, StandardCharsets.UTF_8),
                    secret,
                    URLEncoder.encode(issuer, StandardCharsets.UTF_8)
            );

            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(
                    otpAuth,
                    BarcodeFormat.QR_CODE,
                    300,
                    300
            );
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
                return outputStream.toByteArray();
            }
        } catch (Exception e) {
            throw new RuntimeException("Generate QR Code failed", e);
        }
    }

    @Override
    public String buildOtpAuthUrl(String secret, String username, String issuer) {
        return "";
    }
}
