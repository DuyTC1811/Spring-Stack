package com.example.observability.repository;

import com.example.observability.enums.DisbursementStatus;
import com.example.observability.model.Disbursement;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IDisbursementRepository extends JpaRepository<Disbursement, Long> {

    Optional<Disbursement> findByReference(String reference);

    long countByStatus(DisbursementStatus status);
}
