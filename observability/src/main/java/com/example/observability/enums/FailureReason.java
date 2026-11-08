package com.example.observability.enums;

/**
 * Dùng làm giá trị tag metrics. Tập giá trị phải hữu hạn: mỗi tổ hợp tag là một time series
 * trong Prometheus, nên không bao giờ dùng reference, số tài khoản hay message lỗi làm tag.
 */
public enum FailureReason {
    FX_RATE_UNAVAILABLE,
    UNSUPPORTED_CURRENCY
}
