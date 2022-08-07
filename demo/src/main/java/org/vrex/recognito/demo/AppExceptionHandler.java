package org.vrex.recognito.demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.RestClientException;
import org.vrex.recognito.demo.model.ApplicationException;

@Slf4j
@ControllerAdvice
@SuppressWarnings("unused")
public class AppExceptionHandler {

    @ExceptionHandler(ApplicationException.class)
    public ResponseEntity<?> handleCustomException(ApplicationException exception) {
        return new ResponseEntity<>(
                exception.getErrorMessage() != null ? exception.getErrorMessage() : "Something went wrong",
                exception.getStatus() != null ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(RestClientException.class)
    public ResponseEntity<?> handleRestClientException(RestClientException exception) {
        return new ResponseEntity<>(
                exception.getMessage() != null ? exception.getMessage() : "Something went wrong with the REST client",
                HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
