package com.example.observability.model;

import com.example.observability.enums.DisbursementStatus;
import com.example.observability.exception.IllegalStateTransitionException;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

@Getter
@Setter
@Entity
@AllArgsConstructor
@Table(name = "disbursement", indexes = @Index(name = "idx_disbursement_status", columnList = "status"))
public class Disbursement {
    private static final int REFERENCE_RANDOM_LENGTH = 16;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 40)
    private String reference;

    @Column(nullable = false, precision = 19, scale = 2)
    private BigDecimal amount;

    @Column(nullable = false, length = 3)
    private String currency;

    @Column(name = "fx_rate", nullable = false, precision = 19, scale = 4)
    private BigDecimal fxRate;

    @Column(name = "amount_vnd", nullable = false, precision = 19)
    private BigDecimal amountVnd;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private DisbursementStatus status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "disbursed_at")
    private Instant disbursedAt;

    protected Disbursement() {
        // cho JPA
    }

    public static Disbursement pending(Money amount, BigDecimal fxRate, Instant createdAt) {
        Disbursement disbursement = new Disbursement();
        disbursement.reference = newReference();
        disbursement.amount = amount.amount();
        disbursement.currency = amount.currency().getCurrencyCode();
        disbursement.fxRate = fxRate;
        disbursement.amountVnd = amount.convertToVnd(fxRate);
        disbursement.status = DisbursementStatus.PENDING;
        disbursement.createdAt = createdAt;
        return disbursement;
    }

    public void disburse(Instant disbursedAt) {
        if (status != DisbursementStatus.PENDING) {
            throw new IllegalStateTransitionException(reference, status, DisbursementStatus.DISBURSED);
        }
        this.status = DisbursementStatus.DISBURSED;
        this.disbursedAt = disbursedAt;
    }

    private static String newReference() {
        String random = UUID.randomUUID().toString().replace("-", "").substring(0, REFERENCE_RANDOM_LENGTH);
        return "FX" + random.toUpperCase(Locale.ROOT);
    }

}
