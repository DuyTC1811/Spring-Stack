package com.example.observability.model;

import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;

import java.math.BigDecimal;
import java.util.Currency;

public record CreateDisbursementRequest(
        @NotNull @Positive @Digits(integer = 17, fraction = 2) BigDecimal amount,
        @NotBlank @Pattern(regexp = "[A-Z]{3}") String currency) {

   public Money toMoney() {
        return new Money(amount, Currency.getInstance(currency));
    }
}
