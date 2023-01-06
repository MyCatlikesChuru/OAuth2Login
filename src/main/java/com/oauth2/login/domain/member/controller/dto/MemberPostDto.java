package com.oauth2.login.domain.member.controller.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberPostDto {
    private String email;
    private String username;
    private String password;
}
