package com.oauth2.login.global.security.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
public class LoginDto {
    private String email;
    private String password;
}
