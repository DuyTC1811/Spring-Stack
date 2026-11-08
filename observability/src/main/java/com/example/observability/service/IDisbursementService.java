package com.example.observability.service;

import com.example.observability.model.Disbursement;
import com.example.observability.model.Money;

public interface IDisbursementService {
    Disbursement create(Money amount);

    Disbursement disburse(String reference);

    Disbursement findByReference(String reference);
}
