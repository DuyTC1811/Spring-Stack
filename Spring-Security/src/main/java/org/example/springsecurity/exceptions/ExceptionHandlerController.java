package org.example.springsecurity.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.security.SignatureException;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class ExceptionHandlerController {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExceptionHandlerController.class);

    private static final String GENERIC_BAD_REQUEST = "Invalid request";
    private static final String GENERIC_FORBIDDEN = "Forbidden";
    private static final String GENERIC_UNAUTHORIZED = "Unauthorized";
    private static final String GENERIC_INTERNAL = "Internal server error";

    // Custom Exception: message được app tự định nghĩa nên an toàn để trả về.
    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(BaseException exception) {
        return build(exception.getCode(), exception.getMessage(), exception.getMessage());
    }

    // Validation
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidExceptionResponse> handlerResponse(MethodArgumentNotValidException exception) {
        Map<String, Object> errors = new LinkedHashMap<>();
        exception.getBindingResult().getAllErrors().forEach(error -> {
            if (error instanceof FieldError fieldError) {
                errors.put(fieldError.getField(), fieldError.getDefaultMessage());
            }
        });
        LOGGER.warn("[ EXCEPTION-VALID ] - {}", errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ValidExceptionResponse(HttpStatus.BAD_REQUEST.value(), "Invalid field", errors));
    }

    // Missing request param / path variable
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(MissingServletRequestParameterException exception) {
        LOGGER.warn("[ EXCEPTION ] Missing parameter: {}", exception.getParameterName());
        return build(HttpStatus.BAD_REQUEST.value(), GENERIC_BAD_REQUEST, "Missing required parameter");
    }

    // Request body sai format (JSON parse fail)
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(HttpMessageNotReadableException exception) {
        LOGGER.warn("[ EXCEPTION ] Unreadable body: {}", exception.getMessage());
        return build(HttpStatus.BAD_REQUEST.value(), GENERIC_BAD_REQUEST, "Invalid request body");
    }

    // Sai HTTP method
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(HttpRequestMethodNotSupportedException exception) {
        LOGGER.warn("[ EXCEPTION ] Method not allowed: {}", exception.getMethod());
        return build(HttpStatus.METHOD_NOT_ALLOWED.value(), "Method not allowed", "Method not allowed");
    }

    // Sai Content-Type
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(HttpMediaTypeNotSupportedException exception) {
        LOGGER.warn("[ EXCEPTION ] Unsupported media type: {}", exception.getContentType());
        return build(HttpStatus.UNSUPPORTED_MEDIA_TYPE.value(), "Unsupported media type", "Unsupported media type");
    }

    // 404 - Không tìm thấy resource
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(NoResourceFoundException exception) {
        return build(HttpStatus.NOT_FOUND.value(), "Resource not found", "Resource not found");
    }

    // Type mismatch
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(MethodArgumentTypeMismatchException exception) {
        LOGGER.warn("[ EXCEPTION ] Type mismatch for: {}", exception.getName());
        return build(HttpStatus.BAD_REQUEST.value(), GENERIC_BAD_REQUEST, "Invalid parameter value");
    }

    // Security exceptions
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(BadCredentialsException exception) {
        return build(HttpStatus.UNAUTHORIZED.value(), GENERIC_UNAUTHORIZED, "The username or password is incorrect");
    }

    @ExceptionHandler(AccountStatusException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(AccountStatusException exception) {
        return build(HttpStatus.FORBIDDEN.value(), GENERIC_FORBIDDEN, "The account is locked");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(AccessDeniedException exception) {
        return build(HttpStatus.FORBIDDEN.value(), GENERIC_FORBIDDEN, "You are not authorized to access this resource");
    }

    // JWT exceptions
    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(SignatureException exception) {
        return build(HttpStatus.FORBIDDEN.value(), GENERIC_FORBIDDEN, "The JWT signature is invalid");
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(ExpiredJwtException exception) {
        return build(HttpStatus.FORBIDDEN.value(), GENERIC_FORBIDDEN, "The JWT token has expired");
    }

    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<ExceptionResponse> handlerResponse(MalformedJwtException exception) {
        return build(HttpStatus.FORBIDDEN.value(), GENERIC_FORBIDDEN, "Invalid JWT");
    }

    // Fallback - catch all
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ExceptionResponse> handleInternalException(Exception exception) {
        LOGGER.error("[ EXCEPTION-INTERNAL-SERVER ]", exception);
        return build(HttpStatus.INTERNAL_SERVER_ERROR.value(), GENERIC_INTERNAL, GENERIC_INTERNAL);
    }

    private ResponseEntity<ExceptionResponse> build(int code, String detail, String description) {
        LOGGER.warn("[ EXCEPTION ] code={} detail={}", code, detail);
        return ResponseEntity.status(code).body(new ExceptionResponse(code, detail, description));
    }
}
