package com.oauth2.login.global.security.auth.handler;

import com.google.gson.Gson;
import com.oauth2.login.global.exception.BusinessLogicException;
import com.oauth2.login.global.exception.ExceptionCode;
import com.oauth2.login.global.response.ErrorResponse;
import com.oauth2.login.global.security.auth.utils.ErrorResponder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class MemberAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        log.warn("Forbidden error happened: {}", accessDeniedException.getMessage());
        ErrorResponder.sendErrorResponse(response, HttpStatus.FORBIDDEN);
    }
}
