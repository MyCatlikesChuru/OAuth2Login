package com.oauth2.login.domain.member.controller;


import com.oauth2.login.domain.member.controller.dto.MemberPostDto;
import com.oauth2.login.domain.member.controller.dto.ApiTestDto;
import com.oauth2.login.domain.member.service.MemberService;
import com.oauth2.login.global.security.auth.jwt.TokenProvider;
import com.oauth2.login.global.security.auth.loginresolver.LoginMemberEmail;
import com.oauth2.login.global.security.auth.loginresolver.LoginMemberId;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;


@Slf4j
@RestController
@RequestMapping("/members")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final TokenProvider tokenProvider;

    @GetMapping("/jwt")
    public ResponseEntity getToken(){

        log.info("# secretKey = {}", tokenProvider.getSecretKey());
        log.info("# accessTokenExpirationMinutes = {}", tokenProvider.getAccessTokenExpirationMinutes());
        log.info("# refreshTokenExpirationMinutes = {}", tokenProvider.getRefreshTokenExpirationMinutes());

        return new ResponseEntity(HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity createMember(@RequestBody MemberPostDto memberPostDto){

        memberService.saveMember(memberPostDto);

        return new ResponseEntity(HttpStatus.OK);
    }

    // @AuthenticationPrincipal로 객체 가져오기
    @GetMapping("/principal")
    public ResponseEntity getPrincipal(@AuthenticationPrincipal AuthMember authMember){

        log.info("# authMember.getEmail = {}",authMember.getEmail());
        log.info("# authMember.getId = {}",authMember.getId());
        log.info("# authMember.getAuthorities = {}",authMember.getAuthorities().toString());

        return new ResponseEntity(HttpStatus.CREATED);
    }

    // 커스텀 애노테이션
    @GetMapping("/custom")
    public ResponseEntity getLogin(@LoginMemberEmail String email,
                                   @LoginMemberId Long id){

        log.info("# LoginMemberEmail = {}", email);
        log.info("# LoginMemberId = {}", id);

        return new ResponseEntity(HttpStatus.CREATED);
    }

}
