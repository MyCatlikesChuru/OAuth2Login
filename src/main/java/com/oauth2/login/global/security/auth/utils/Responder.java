package com.oauth2.login.global.security.auth.utils;

import com.google.gson.Gson;
import com.oauth2.login.domain.member.controller.dto.LoginResponseDto;
import com.oauth2.login.global.exception.BusinessLogicException;
import com.oauth2.login.global.exception.ExceptionCode;
import com.oauth2.login.global.response.ErrorResponse;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Responder {
    public static void sendErrorResponse(HttpServletResponse response, HttpStatus status) throws IOException {
        Gson gson = new Gson();
        ErrorResponse errorResponse = ErrorResponse.of(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status.value());
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));
    }

    public static void sendErrorResponse(HttpServletResponse response, ExceptionCode code) {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        throw new BusinessLogicException(code);
    }

    public static void loginSuccessResponse(HttpServletResponse response, AuthMember authMember) throws IOException {
        Gson gson = new Gson();
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        LoginResponseDto loginResponse = LoginResponseDto.builder()
                .id(authMember.getId())
                .email(authMember.getEmail())
                .role(authMember.getRoles().get(0))
                .build();

        response.getWriter().write(gson.toJson(loginResponse, LoginResponseDto.class));
    }
}
