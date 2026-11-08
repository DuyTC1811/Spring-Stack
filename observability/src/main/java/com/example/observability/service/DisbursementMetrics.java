package com.example.observability.service;

import com.example.observability.enums.DisbursementStatus;
import com.example.observability.enums.FailureReason;
import com.example.observability.model.Disbursement;
import com.example.observability.repository.IDisbursementRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Metrics nghiệp vụ. Tên dạng "a.b.c" được Micrometer đổi sang chuẩn Prometheus:
 * disbursement.created → disbursement_created_total, disbursement.amount (vnd) → disbursement_amount_vnd_*.
 */
@Component
public class DisbursementMetrics {
    private static final String CURRENCY_TAG = "currency";

    private final MeterRegistry registry;

    public DisbursementMetrics(MeterRegistry registry, IDisbursementRepository repository) {
        this.registry = registry;
        // Gauge chạy count(*) mỗi lần Prometheus scrape (15s); rẻ vì có index trên status
        Gauge.builder("disbursement.pending", repository,
                        repo -> repo.countByStatus(DisbursementStatus.PENDING)
                ).description("Số lệnh giải ngân đang chờ xử lý")
                .register(registry);
    }

    public void recordCreated(Disbursement disbursement) {
        Counter.builder("disbursement.created")
                .description("Số lệnh giải ngân đã tạo")
                .tag(CURRENCY_TAG, disbursement.getCurrency())
                .register(registry)
                .increment();
        DistributionSummary.builder("disbursement.amount")
                .description("Giá trị giải ngân quy đổi VND")
                .baseUnit("vnd")
                .tag(CURRENCY_TAG, disbursement.getCurrency())
                .register(registry)
                .record(disbursement.getAmountVnd().doubleValue());
    }

    public void recordDisbursed(Disbursement disbursement) {
        Counter.builder("disbursement.disbursed")
                .description("Số lệnh đã giải ngân")
                .tag(CURRENCY_TAG, disbursement.getCurrency())
                .register(registry)
                .increment();
    }

    public void recordFailure(FailureReason reason) {
        Counter.builder("disbursement.failed")
                .description("Số lệnh tạo thất bại theo nguyên nhân")
                .tag("reason", reason.name())
                .register(registry)
                .increment();
    }
}
