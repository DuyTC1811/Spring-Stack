package org.example.springsecurity.handlers;

public interface ITwoFactorService {
    /**
     * Khởi tạo flow 2FA cho user: sinh secret mới, lưu tạm trong cache theo username,
     * trả về QR code để user scan bằng Authenticator app.
     */
    byte[] beginSetup(String username);

    /**
     * Xác nhận code user nhập sau khi scan QR. Nếu hợp lệ, kích hoạt 2FA cho username.
     */
    boolean confirmSetup(String username, String code);

    /**
     * Verify code cho user đã bật 2FA.
     */
    boolean verifyCode(String username, String code);
}
