package com.example.observability.model;

import com.example.observability.enums.DisbursementStatus;

import java.math.BigDecimal;
import java.time.Instant;

public record DisbursementResponse(
        String reference,
        BigDecimal amount,
        String currency,
        BigDecimal fxRate,
        BigDecimal amountVnd,
        DisbursementStatus status,
        Instant createdAt,
        Instant disbursedAt
) {
    public static DisbursementResponse from(Disbursement disbursement) {
        return new DisbursementResponse(
                disbursement.getReference(),
                disbursement.getAmount(),
                disbursement.getCurrency(),
                disbursement.getFxRate(),
                disbursement.getAmountVnd(),
                disbursement.getStatus(),
                disbursement.getCreatedAt(),
                disbursement.getDisbursedAt()
        );
    }
}
