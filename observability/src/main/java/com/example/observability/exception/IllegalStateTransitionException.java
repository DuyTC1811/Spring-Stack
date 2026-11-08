package com.example.observability.exception;

import com.example.observability.enums.DisbursementStatus;

public class IllegalStateTransitionException extends RuntimeException {
    public IllegalStateTransitionException(String reference, DisbursementStatus from, DisbursementStatus to) {
        super("Disbursement %s cannot move from %s to %s".formatted(reference, from, to));
    }
}
