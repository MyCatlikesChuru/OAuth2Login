package com.oauth2.login.domain.member.service;

import com.oauth2.login.domain.member.controller.dto.MemberPostDto;
import com.oauth2.login.domain.member.entity.Member;
import com.oauth2.login.domain.member.repository.MemberRepository;
import com.oauth2.login.global.security.auth.oauth.OAuthUserProfile;
import com.oauth2.login.global.security.auth.utils.CustomAuthorityUtils;
import com.oauth2.login.global.security.config.PasswordEncoderConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final CustomAuthorityUtils customAuthorityUtils;

    private final PasswordEncoder passwordEncoder;

    public Member saveMember(MemberPostDto memberPostDto){

        String encryptedPassword = passwordEncoder.encode(memberPostDto.getPassword());

        Member member = Member.builder()
                .email(memberPostDto.getEmail())
                .username(memberPostDto.getUsername())
                .password(encryptedPassword)
                .roles(customAuthorityUtils.createRoles(memberPostDto.getEmail()))
                .build();

        return memberRepository.save(member);
    }

    // OAuth2 인증 완료후 회원가입 및 업데이트
    public Member saveMemberOauth(OAuthUserProfile userProfile, List<String> roles) {
        Member member = memberRepository.findByEmail(userProfile.getEmail())
                .map(m -> m.oauthUpdate(userProfile.getName(), userProfile.getEmail(), roles)) // 변경감지 Update
                .orElse(userProfile.createOauth2Member(userProfile.getName(), userProfile.getEmail(),roles));
        return memberRepository.save(member);
    }

}
