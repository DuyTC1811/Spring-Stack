package com.example.observability.service;

import com.example.observability.enums.FailureReason;
import com.example.observability.exception.DisbursementNotFoundException;
import com.example.observability.exception.FxRateUnavailableException;
import com.example.observability.exception.UnsupportedCurrencyException;
import com.example.observability.model.Disbursement;
import com.example.observability.model.Money;
import com.example.observability.repository.IDisbursementRepository;
import io.micrometer.core.annotation.Timed;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Clock;
import java.util.Currency;

@Slf4j
@Service
@RequiredArgsConstructor
public class DisbursementService implements IDisbursementService{

    private final IDisbursementRepository repository;
    private final FxRateProvider fxRateProvider;
    private final DisbursementMetrics metrics;
    private final Clock clock;

    /*
     * Không đặt @Transactional ở đây: gọi HTTP lấy tỷ giá bên trong transaction sẽ giữ
     * connection DB suốt thời gian chờ và làm cạn Hikari pool khi nguồn tỷ giá chậm.
     */
    @Override
    @Timed(value = "disbursement.create", description = "Thời gian tạo lệnh giải ngân", histogram = true)
    public Disbursement create(Money amount) {
        BigDecimal fxRate = fetchRate(amount.currency());
        Disbursement disbursement = repository.save(Disbursement.pending(amount, fxRate, clock.instant()));

        // reference có cardinality cao: chỉ ghi vào log (OBI chèn trace_id), KHÔNG làm tag metrics
        metrics.recordCreated(disbursement);
        log.info("Created disbursement reference={} currency={} amountVnd={}",
                disbursement.getReference(), disbursement.getCurrency(), disbursement.getAmountVnd());
        return disbursement;
    }

    @Override
    @Transactional
    public Disbursement disburse(String reference) {
        Disbursement disbursement = findByReference(reference);
        disbursement.disburse(clock.instant());
        metrics.recordDisbursed(disbursement);
        log.info("Disbursed reference={}", reference);
        return disbursement;
    }

    @Override
    @Transactional
    public Disbursement findByReference(String reference) {
        return repository.findByReference(reference)
                .orElseThrow(() -> new DisbursementNotFoundException(reference)
                );
    }

    private BigDecimal fetchRate(Currency currency) {
        try {
            return fxRateProvider.getRate(currency);
        } catch (FxRateUnavailableException e) {
            metrics.recordFailure(FailureReason.FX_RATE_UNAVAILABLE);
            throw e;
        } catch (UnsupportedCurrencyException e) {
            metrics.recordFailure(FailureReason.UNSUPPORTED_CURRENCY);
            throw e;
        }
    }
}
