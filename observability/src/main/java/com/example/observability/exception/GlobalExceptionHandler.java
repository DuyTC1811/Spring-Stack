package com.example.observability.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DisbursementNotFoundException.class)
    public ProblemDetail handleNotFound(DisbursementNotFoundException ex) {
        return problem(HttpStatus.NOT_FOUND, "DISBURSEMENT_NOT_FOUND", ex);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleInvalidRequest(IllegalArgumentException ex) {
        return problem(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", ex);
    }

    @ExceptionHandler(UnsupportedCurrencyException.class)
    public ProblemDetail handleUnsupportedCurrency(UnsupportedCurrencyException ex) {
        return problem(HttpStatus.UNPROCESSABLE_ENTITY, "UNSUPPORTED_CURRENCY", ex);
    }

    @ExceptionHandler(IllegalStateTransitionException.class)
    public ProblemDetail handleIllegalTransition(IllegalStateTransitionException ex) {
        return problem(HttpStatus.CONFLICT, "ILLEGAL_STATE_TRANSITION", ex);
    }

    @ExceptionHandler(FxRateUnavailableException.class)
    public ProblemDetail handleFxRateUnavailable(FxRateUnavailableException ex) {
        log.warn("FX rate source failed", ex);
        return problem(HttpStatus.SERVICE_UNAVAILABLE, "FX_RATE_UNAVAILABLE", ex);
    }

    private static ProblemDetail problem(HttpStatus status, String errorCode, Exception ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        problem.setProperty("errorCode", errorCode);
        return problem;
    }
}
