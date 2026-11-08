package com.example.observability.model;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Currency;
import java.util.Objects;

public record Money(BigDecimal amount, Currency currency) {
    public Money {
        Objects.requireNonNull(amount, "amount");
        Objects.requireNonNull(currency, "currency");
        if (amount.signum() <= 0) {
            throw new IllegalArgumentException("Amount must be positive: " + amount);
        }
    }

    public static Money of(String amount, String currencyCode) {
        return new Money(new BigDecimal(amount), Currency.getInstance(currencyCode));
    }

    public BigDecimal convertToVnd(BigDecimal fxRate) {
        // VND không có phần lẻ; làm tròn xuống để không giải ngân vượt số tiền quy đổi
        return amount.multiply(fxRate).setScale(0, RoundingMode.DOWN);
    }
}
