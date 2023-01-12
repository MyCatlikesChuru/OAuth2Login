package com.oauth2.login.domain.member.service;

import com.oauth2.login.domain.member.controller.dto.MemberPostDto;
import com.oauth2.login.domain.member.entity.Member;
import com.oauth2.login.domain.member.repository.MemberRepository;
import com.oauth2.login.global.common.redis.RedisDao;
import com.oauth2.login.global.exception.BusinessLogicException;
import com.oauth2.login.global.exception.ExceptionCode;
import com.oauth2.login.global.security.auth.jwt.TokenProvider;
import com.oauth2.login.global.security.auth.oauth.OAuthUserProfile;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import com.oauth2.login.global.security.auth.utils.CustomAuthorityUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final CustomAuthorityUtils customAuthorityUtils;

    private final PasswordEncoder passwordEncoder;

    // 일반 회원가입
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
                .map(m -> m.oauthUpdate(userProfile.getName(), userProfile.getEmail(), userProfile.getImage(), roles)) // 변경감지 Update
                .orElse(userProfile.createOauth2Member(userProfile.getName(), userProfile.getEmail(), userProfile.getImage(), roles));
        return memberRepository.save(member);
    }

}
