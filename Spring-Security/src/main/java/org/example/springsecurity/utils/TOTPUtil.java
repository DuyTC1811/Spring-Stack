package org.example.springsecurity.utils;

import lombok.experimental.UtilityClass;
import org.apache.commons.codec.binary.Base32;
import org.example.springsecurity.enums.HmacAlgorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@UtilityClass
public class TOTPUtil {

    private static final int MIN_DIGITS = 6;
    private static final int MAX_DIGITS = 8;
    private static final int[] POWERS_OF_10 = {
            1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000
    };

    // MẶC ĐỊNH TƯƠNG THÍCH GOOGLE AUTHENTICATOR
    private static final HmacAlgorithm DEFAULT_ALGORITHM = HmacAlgorithm.SHA1;
    private static final int DEFAULT_DIGITS = 6;
    private static final Duration DEFAULT_TIME_STEP = Duration.ofSeconds(30);

    /**
     * Sinh secret 160-bit ngẫu nhiên, encode Base32 để tương thích Google Authenticator,
     * Microsoft Authenticator, Authy và các TOTP app phổ biến khác.
     *
     * <p>RFC 4226 khuyến nghị secret dài tối thiểu 128 bit, tốt nhất là 160 bit
     * (bằng với output size của HMAC-SHA1). Độ dài 20 bytes = 160 bit được chọn
     * vì vừa đủ mạnh cho mục đích TOTP, vừa tối ưu cho HMAC-SHA1.
     *
     * <p>Dùng {@link SecureRandom} (CSPRNG) thay vì {@link java.util.Random}
     * để đảm bảo tính không đoán trước được - nếu dùng Random với seed từ
     * {@code currentTimeMillis()}, attacker có thể brute-force seed và tái tạo
     * toàn bộ secret đã sinh.
     *
     * <p>Base32 được dùng thay vì Base64 vì:
     * <ul>
     *   <li>Không phân biệt hoa thường - user dễ nhập tay nếu cần</li>
     *   <li>Không có ký tự dễ nhầm lẫn (0/O, 1/I/l)</li>
     *   <li>Là format chuẩn trong otpauth:// URI của Google Authenticator</li>
     * </ul>
     *
     * @return secret dạng Base32, độ dài 32 ký tự (ví dụ: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
     */
    public static String generateSecret() {
        byte[] buffer = new byte[20]; // 160 bit - RFC 4226 recommended
        new SecureRandom().nextBytes(buffer);
        return new Base32().encodeToString(buffer);
    }

    /**
     * TOTP với cấu hình mặc định (SHA1, 6 digits, 30s).
     */
    public static String generateTotp(byte[] secret) {
        return generateTotp(secret, Instant.now(), DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_TIME_STEP);
    }

    /**
     * TOTP với cấu hình tùy chỉnh.
     */
    private String generateTotp(byte[] secret, Instant at, HmacAlgorithm algorithm, int digits, Duration timeStep) {
        validateConfig(algorithm, digits, timeStep);
        Objects.requireNonNull(at, "at must not be null");
        long timeIndex = at.getEpochSecond() / timeStep.getSeconds();
        return generateHotp(secret, timeIndex, algorithm, digits);
    }

    /**
     * Verify TOTP code, cho phép lệch đồng hồ ±{@code window} time step.
     *
     * <p>Đồng hồ client và server thường lệch nhau vài giây, dẫn đến hai bên
     * tính ra code khác nhau. Window giải quyết bằng cách check thêm các step
     * lân cận. Ví dụ {@code window = 1} với timeStep 30s → chấp nhận lệch ±30s.
     *
     * <p>Window càng lớn càng dễ bị brute-force. Khuyến nghị dùng {@code window = 1}.
     *
     * @param window số time step chấp nhận mỗi phía, phải {@code >= 0}
     * @return {@code true} nếu code khớp, {@code false} nếu không hoặc input invalid
     */
    public static boolean verifyTotp(byte[] secret, String code, int window) {
        return verifyTotp(secret, code, window, Instant.now(), DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_TIME_STEP);
    }

    /**
     * Verify TOTP với cấu hình tùy chỉnh và thời điểm cụ thể.
     *
     * <p>Duyệt qua các time step trong khoảng [-window, +window] quanh {@code at},
     * sinh HOTP code cho từng step và so sánh constant-time với {@code code} user nhập.
     * Dùng constant-time để tránh timing attack.
     *
     * @param secret    khóa bí mật (đã decode từ Base32)
     * @param code      code user nhập, phải đúng độ dài {@code digits}
     * @param window    số time step chấp nhận mỗi phía, phải {@code >= 0}
     * @param at        thời điểm verify (dùng {@link Instant#now()} thực tế, inject khi test)
     * @param algorithm thuật toán HMAC (SHA1/SHA256/SHA512)
     * @param digits    độ dài code (6-8)
     * @param timeStep  độ dài mỗi time step (thường 30s)
     * @return {@code true} nếu code khớp với ít nhất một step trong window
     * @throws IllegalArgumentException nếu {@code window < 0} hoặc config invalid
     */
    private boolean verifyTotp(byte[] secret, String code, int window, Instant at, HmacAlgorithm algorithm, int digits, Duration timeStep) {
        validateConfig(algorithm, digits, timeStep);
        if (code == null || code.length() != digits) {
            return false;
        }
        if (window < 0) {
            throw new IllegalArgumentException("window must be >= 0");
        }
        long currentIndex = at.getEpochSecond() / timeStep.getSeconds();
        for (int i = -window; i <= window; i++) {
            String expected = generateHotp(secret, currentIndex + i, algorithm, digits);
            if (constantTimeEquals(expected, code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sinh HOTP code theo RFC 4226 - hàm core cho cả HOTP và TOTP.
     *
     * <p>Thuật toán gồm 3 bước:
     * <ol>
     *   <li><b>HMAC</b>: tính HMAC của {@code counter} (8 bytes big-endian) với {@code secret}</li>
     *   <li><b>Dynamic Truncation</b>: lấy 4 bit cuối của hash làm offset, rồi lấy 4 bytes
     *       liên tiếp từ offset đó. Mask {@code 0x7f} byte đầu để xóa bit dấu, tránh
     *       vấn đề signed integer</li>
     *   <li><b>Modulo</b>: chia lấy dư {@code 10^digits} để được code có đúng số chữ số
     *       mong muốn, rồi pad leading zeros</li>
     * </ol>
     *
     * <p>TOTP chỉ khác HOTP ở chỗ {@code counter = currentTime / timeStep} thay vì
     * counter tăng dần.
     *
     * @param secret    khóa bí mật, không được null hoặc rỗng
     * @param counter   giá trị counter (HOTP) hoặc time index (TOTP)
     * @param algorithm thuật toán HMAC (SHA1/SHA256/SHA512)
     * @param digits    độ dài code mong muốn (6-8)
     * @return code đã pad leading zeros, độ dài đúng bằng {@code digits}
     * @throws IllegalArgumentException nếu input invalid hoặc key không hợp lệ
     * @throws IllegalStateException    nếu JDK không hỗ trợ thuật toán (hiếm khi xảy ra)
     */
    private String generateHotp(byte[] secret, long counter, HmacAlgorithm algorithm, int digits) {
        Objects.requireNonNull(secret, "secret must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        if (secret.length == 0) {
            throw new IllegalArgumentException("secret must not be empty");
        }
        if (digits < MIN_DIGITS || digits > MAX_DIGITS) {
            throw new IllegalArgumentException(
                    "digits must be between " + MIN_DIGITS + " and " + MAX_DIGITS);
        }

        try {
            Mac mac = Mac.getInstance(algorithm.getMacName());
            mac.init(new SecretKeySpec(secret, algorithm.getMacName()));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(counter).array());

            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);

            int otp = binary % POWERS_OF_10[digits];
            return padLeftZeros(otp, digits);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HMAC algorithm not available: " + algorithm.getMacName(), e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Invalid secret key", e);
        }
    }

    /**
     * Validate cấu hình TOTP/HOTP trước khi sinh hoặc verify code.
     *
     * @throws NullPointerException     nếu {@code algorithm} hoặc {@code timeStep} null
     * @throws IllegalArgumentException nếu {@code digits} ngoài khoảng [{@value #MIN_DIGITS},
     *                                  {@value #MAX_DIGITS}] hoặc {@code timeStep} không dương
     */
    private void validateConfig(HmacAlgorithm algorithm, int digits, Duration timeStep) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(timeStep, "timeStep must not be null");
        if (digits < MIN_DIGITS || digits > MAX_DIGITS) {
            throw new IllegalArgumentException(
                    "digits must be between " + MIN_DIGITS + " and " + MAX_DIGITS);
        }
        if (timeStep.isZero() || timeStep.isNegative()) {
            throw new IllegalArgumentException("timeStep must be positive");
        }
    }

    /**
     * So sánh hai chuỗi trong thời gian không đổi (constant-time) để chống timing attack.
     *
     * <p>{@link String#equals} short-circuit ngay khi gặp ký tự khác nhau đầu tiên,
     * nên thời gian thực thi phụ thuộc vào vị trí ký tự sai. Attacker có thể đo
     * response time để đoán dần từng ký tự của code đúng.
     *
     * <p>Hàm này luôn duyệt hết toàn bộ chuỗi bằng phép XOR tích lũy vào {@code result}.
     * Thời gian thực thi chỉ phụ thuộc vào độ dài, không phụ thuộc vào vị trí ký tự sai.
     *
     * @return {@code true} nếu hai chuỗi giống hệt nhau
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    /**
     * Pad số 0 vào bên trái cho đủ {@code length} ký tự.
     *
     * <p>Cần thiết vì TOTP là chuỗi có độ dài cố định - code {@code 12345} với 6 digits
     * phải hiển thị là {@code "012345"}, không phải {@code "12345"}.
     *
     * @param value  giá trị không âm cần format
     * @param length độ dài chuỗi đích
     * @return chuỗi đã pad, ví dụ {@code padLeftZeros(123, 6) = "000123"}
     */
    //@formatter:off
    private static String padLeftZeros(int value, int length) {
        switch (length) {
            case 6:
                if (value >= 100_000) return Integer.toString(value);
                if (value >= 10_000)  return "0" + value;
                if (value >= 1_000)   return "00" + value;
                if (value >= 100)     return "000" + value;
                if (value >= 10)      return "0000" + value;
                return "00000" + value;
            case 7:
                if (value >= 1_000_000) return Integer.toString(value);
                if (value >= 100_000)   return "0" + value;
                if (value >= 10_000)    return "00" + value;
                if (value >= 1_000)     return "000" + value;
                if (value >= 100)       return "0000" + value;
                if (value >= 10)        return "00000" + value;
                return "000000" + value;
            case 8:
                if (value >= 10_000_000) return Integer.toString(value);
                if (value >= 1_000_000)  return "0" + value;
                if (value >= 100_000)    return "00" + value;
                if (value >= 10_000)     return "000" + value;
                if (value >= 1_000)      return "0000" + value;
                if (value >= 100)        return "00000" + value;
                if (value >= 10)         return "000000" + value;
                return "0000000" + value;
            default:
                return String.format("%0" + length + "d", value);
        }
    }
    //@formatter:on
}
