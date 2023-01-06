package com.oauth2.login.global.response;

import com.oauth2.login.global.exception.ExceptionCode;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;

@Getter
public class ErrorResponse {
    private int status;
    private String message;
    private ErrorResponse(int status, String message) {
        this.status = status;
        this.message = message;
    }

    private ErrorResponse(final ExceptionCode code) {
        this.message = code.getMessage();
        this.status = code.getStatus();
    }

    public static ErrorResponse of(HttpStatus httpStatus) {
        return new ErrorResponse(httpStatus.value(), httpStatus.getReasonPhrase());
    }

    public static ErrorResponse of(final ExceptionCode code) {
        return new ErrorResponse(code);
    }
}