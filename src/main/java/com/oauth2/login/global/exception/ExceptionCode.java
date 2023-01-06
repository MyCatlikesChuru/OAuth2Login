package com.oauth2.login.global.exception;

import lombok.Getter;

@Getter
public enum ExceptionCode {
    /* JWT */
    ACCESS_TOKEN_NOT_FOUND(404,"액세스토큰을 찾을 수 없습니다."),
    TOKEN_EXPIRED(400, "Token Expired"),
    TOKEN_INVALID(400, "Token Invalid"),
    TOKEN_SIGNATURE_INVALID(400, "Token Signature Invalid"),
    TOKEN_MALFORMED(400, "Token Malformed"),
    TOKEN_UNSUPPORTED(400, "Token Unsupported"),
    TOKEN_ILLEGAL_ARGUMENT(400, "Token Illegal Argument");

    private int status;

    private String message;

    ExceptionCode(int code, String message) {
        this.status = code;
        this.message = message;
    }
}
