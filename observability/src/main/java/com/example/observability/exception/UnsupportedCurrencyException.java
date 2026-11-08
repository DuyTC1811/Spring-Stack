package com.example.observability.exception;

public class UnsupportedCurrencyException extends RuntimeException {
    public UnsupportedCurrencyException(String currency, Throwable cause) {
        super("Unsupported currency: " + currency, cause);
    }
}
