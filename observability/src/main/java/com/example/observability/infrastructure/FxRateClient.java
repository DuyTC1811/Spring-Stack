package com.example.observability.infrastructure;

import com.example.observability.exception.FxRateUnavailableException;
import com.example.observability.exception.UnsupportedCurrencyException;
import com.example.observability.service.FxRateProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.math.BigDecimal;
import java.util.Currency;

@Component
public class FxRateClient implements FxRateProvider {
    private final RestClient restClient;

    // Dùng RestClient.Builder do Spring cấp: có sẵn timeout từ config và metrics http.client.requests
    FxRateClient(@Value("${fx.base-url}") String baseUrl) {
        RestClient.Builder builder = RestClient.builder();
        this.restClient = builder.baseUrl(baseUrl).build();
    }

    @Override
    public BigDecimal getRate(Currency currency) {
        String code = currency.getCurrencyCode();
        try {
            FxRateResponse response = restClient.get()
                    .uri("/internal/fx-rates/{currency}", code)
                    .retrieve()
                    .body(FxRateResponse.class);
            if (response == null) {
                throw new FxRateUnavailableException(code, null);
            }
            return response.rate();
        } catch (HttpClientErrorException.NotFound e) {
            throw new UnsupportedCurrencyException(code, e);
        } catch (RestClientException e) {
            throw new FxRateUnavailableException(code, e);
        }
    }

    record FxRateResponse(String currency, BigDecimal rate) {
    }
}
