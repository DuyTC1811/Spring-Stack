package com.example.observability.exception;

public class FxRateUnavailableException extends RuntimeException {
    public FxRateUnavailableException(String currency, Throwable cause) {
        super("FX rate unavailable for " + currency, cause);
    }
}
