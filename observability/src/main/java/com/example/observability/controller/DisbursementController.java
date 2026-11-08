package com.example.observability.controller;

import com.example.observability.model.CreateDisbursementRequest;
import com.example.observability.model.Disbursement;
import com.example.observability.model.DisbursementResponse;
import com.example.observability.service.DisbursementService;
import com.example.observability.service.IDisbursementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/disbursements")
public class DisbursementController {
    private final IDisbursementService service;

    @PostMapping
    public ResponseEntity<DisbursementResponse> create(@Valid @RequestBody CreateDisbursementRequest request) {
        Disbursement disbursement = service.create(request.toMoney());
        URI location = URI.create("/api/disbursements/" + disbursement.getReference());
        return ResponseEntity.created(location).body(DisbursementResponse.from(disbursement));
    }

    @GetMapping("/{reference}")
    DisbursementResponse get(@PathVariable String reference) {
        return DisbursementResponse.from(service.findByReference(reference));
    }

    @PostMapping("/{reference}/disburse")
    DisbursementResponse disburse(@PathVariable String reference) {
        return DisbursementResponse.from(service.disburse(reference));
    }
}


