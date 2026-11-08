package com.example.observability.exception;

public class DisbursementNotFoundException extends RuntimeException {
    public DisbursementNotFoundException(String reference) {
        super("Disbursement not found: " + reference);
    }
}
