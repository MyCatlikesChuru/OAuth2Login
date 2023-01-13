package com.oauth2.login.domain.member.service;

import com.oauth2.login.domain.member.controller.dto.MemberPostDto;
import com.oauth2.login.domain.member.entity.Member;
import com.oauth2.login.domain.member.repository.MemberRepository;
import com.oauth2.login.global.common.redis.RedisDao;
import com.oauth2.login.global.exception.BusinessLogicException;
import com.oauth2.login.global.exception.ExceptionCode;
import com.oauth2.login.global.security.auth.dto.TokenDto;
import com.oauth2.login.global.security.auth.jwt.TokenProvider;
import com.oauth2.login.global.security.auth.oauth.OAuthUserProfile;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import com.oauth2.login.global.security.auth.utils.CustomAuthorityUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final CustomAuthorityUtils customAuthorityUtils;

    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;
    private final RedisDao redisDao;

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

    public Member findVerifiedMember(String email){
        Optional<Member> optionalMember = memberRepository.findByEmail(email);
        return optionalMember.orElseThrow(() ->
                new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));
    }

    public void reissueAccessToken(String refreshToken, HttpServletRequest request, HttpServletResponse response){

        if(refreshToken == null){
            throw new BusinessLogicException(ExceptionCode.COOKIE_REFRESH_TOKEN_NOT_FOUND);
        }

        String accessToken = tokenProvider.resolveToken(request);
        String redisAccessToken = redisDao.getValues(refreshToken);

        // Refresh Token이 Redis에 존재할 경우 Access Token 생성
        if(redisDao.validateValue(redisAccessToken) && accessToken.equals(redisAccessToken)){
            log.info("# RefreshToken을 통한 AccessToken 재발급 시작");
            Claims claims = tokenProvider.parseClaims(refreshToken); // Refresh Token 복호화
            String email = claims.get("sub", String.class); // Refresh Token에서 email정보 가져오기
            Member member = findVerifiedMember(email); // DB에서 사용자 정보 찾기
            AuthMember authMember = AuthMember.of(member.getId(), member.getEmail(), member.getRoles());
            TokenDto tokenDto = tokenProvider.generateTokenDto(authMember); // Token 만들기
            int refreshTokenExpirationMinutes = tokenProvider.getRefreshTokenExpirationMinutes();
            redisDao.setValues(refreshToken, tokenDto.getAccessToken(), Duration.ofMinutes(refreshTokenExpirationMinutes));
            tokenProvider.accessTokenSetHeader(tokenDto.getAccessToken(),response);

        } else if(!redisDao.validateValue(redisAccessToken)){
            throw new BusinessLogicException(ExceptionCode.REFRESH_TOKEN_NOT_FOUND);
        } else {
            throw new BusinessLogicException(ExceptionCode.TOKEN_IS_NOT_SAME);
        }
    }
}
