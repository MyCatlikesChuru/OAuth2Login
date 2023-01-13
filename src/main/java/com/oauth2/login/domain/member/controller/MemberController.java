package com.oauth2.login.domain.member.controller;


import com.oauth2.login.domain.member.controller.dto.MemberPostDto;
import com.oauth2.login.domain.member.controller.dto.ApiTestDto;
import com.oauth2.login.domain.member.service.MemberService;
import com.oauth2.login.global.exception.BusinessLogicException;
import com.oauth2.login.global.exception.ExceptionCode;
import com.oauth2.login.global.security.auth.dto.TokenDto;
import com.oauth2.login.global.security.auth.jwt.TokenProvider;
import com.oauth2.login.global.security.auth.loginresolver.LoginMemberEmail;
import com.oauth2.login.global.security.auth.loginresolver.LoginMemberId;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


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

    // 로그인하여 클라이언트에 쿠키 테스트 (리다이렉트 시키기)
    @GetMapping("/redirect")
    public void getCookie(HttpServletResponse response) throws IOException {

        log.info("# Redirect 시작");
        response.sendRedirect("http://localhost:8080/members/login");
    }


    @GetMapping("/reissue")
    public ResponseEntity reissue(@CookieValue(value = "refreshToken", required = false) String refreshToken,
                                  HttpServletRequest request,
                                  HttpServletResponse response){

        memberService.reissueAccessToken(refreshToken,request,response);
        return new ResponseEntity("Refresh Token 재발급 완료!",HttpStatus.CREATED);
    }
}
