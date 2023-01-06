package com.oauth2.login.global.security.auth.utils;

import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ErrorResponder {
    public static void sendErrorResponse(HttpServletResponse response, HttpStatus status) throws IOException {

        // 에러 응답내용 만들어 주기 (커스터 마이징)
    }
}
