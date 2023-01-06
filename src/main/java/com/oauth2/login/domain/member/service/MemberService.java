package com.oauth2.login.domain.member.service;

import com.oauth2.login.domain.member.controller.dto.MemberPostDto;
import com.oauth2.login.domain.member.entity.Member;
import com.oauth2.login.domain.member.repository.MemberRepository;
import com.oauth2.login.global.security.auth.utils.CustomAuthorityUtils;
import com.oauth2.login.global.security.config.PasswordEncoderConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

}
