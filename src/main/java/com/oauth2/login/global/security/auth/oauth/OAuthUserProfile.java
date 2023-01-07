package com.oauth2.login.global.security.auth.oauth;

import com.oauth2.login.domain.member.entity.Member;
import lombok.Getter;

import java.util.List;

@Getter
public class OAuthUserProfile {
    private final String name;
    private final String email;
    private final String oauthId;

    public OAuthUserProfile(String name, String email, String oauthId) {
        this.name = name;
        this.email = email;
        this.oauthId = oauthId;
    }

    public Member createOauth2Member(String name, String email, List<String> roles) {
        return Member.builder()
                .username(name) //이메일
                .email(email) // 이름
                .password(oauthId) // 고유값
                .roles(roles)
                .build();
    }
}
