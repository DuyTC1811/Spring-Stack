package com.example.observability.model;

import java.math.BigDecimal;

public record FxRate(String currency, BigDecimal rate) {
}
