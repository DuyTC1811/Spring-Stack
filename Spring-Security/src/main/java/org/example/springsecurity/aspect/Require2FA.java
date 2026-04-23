package org.example.springsecurity.aspect;

import org.example.springsecurity.enums.ESensitivityLevel;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Require2FA {
    /**
     * Preset sensitivity level với TTL mặc định.
     * Dùng khi action thuộc 1 trong các nhóm chuẩn.
     */
    ESensitivityLevel level() default ESensitivityLevel.HIGH;

    /**
     * TTL tùy chỉnh (phút). Nếu > 0 sẽ override giá trị của `level`.
     * Dùng khi cần TTL đặc biệt không khớp với preset nào.
     * Giá trị -1 (default) nghĩa là dùng theo `level`.
     */
    int customMinutes() default -1;
}
