package com.example.observability.fxstub;

import com.example.observability.model.FxRate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Giả lập dịch vụ tỷ giá bên ngoài để demo: span HTTP client → server, latency dao động và lỗi 503.
 */
@RestController
@RequestMapping("/internal/fx-rates")
public class FxRateStubController {
    private static final Map<String, BigDecimal> RATES = Map.of(
            "USD", new BigDecimal("25400"),
            "EUR", new BigDecimal("27500"),
            "JPY", new BigDecimal("170.5")
    );
    private static final double ERROR_RATE = 0.05;
    private static final int MAX_LATENCY_MS = 400;

    @GetMapping("/{currency}")
    public ResponseEntity<FxRate> getRate(@PathVariable String currency) throws InterruptedException {
        Thread.sleep(ThreadLocalRandom.current().nextInt(MAX_LATENCY_MS));

        if (ThreadLocalRandom.current().nextDouble() < ERROR_RATE) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        BigDecimal rate = RATES.get(currency);
        if (rate == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(new FxRate(currency, rate));
    }
}
