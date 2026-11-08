package com.example.observability.service;

import java.math.BigDecimal;
import java.util.Currency;

public interface FxRateProvider {
    BigDecimal getRate(Currency currency);
}
