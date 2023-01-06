package com.oauth2.login.domain.member.controller;


import com.oauth2.login.domain.member.controller.dto.MemberPostDto;
import com.oauth2.login.domain.member.service.MemberService;
import com.oauth2.login.global.security.auth.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

        return new ResponseEntity(HttpStatus.CREATED);
    }



}
