package com.oauth2.login.global.security.auth.oauth;

import com.oauth2.login.domain.member.entity.Member;

public class OAuthUserProfile {
    private final String name;
    private final String email;
    private final String oauthId;

    public OAuthUserProfile(String name, String email, String oauthId) {
        this.name = name;
        this.email = email;
        this.oauthId = oauthId;
    }

    public Member createOauth2Member() {
        return Member.builder()
                .username(name) //이메일
                .email(email) // 이름
                .password(oauthId) // 고유값
                .build();
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }
}