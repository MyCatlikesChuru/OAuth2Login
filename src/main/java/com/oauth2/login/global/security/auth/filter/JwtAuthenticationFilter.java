package com.oauth2.login.global.security.auth.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.oauth2.login.global.common.redis.RedisDao;
import com.oauth2.login.global.security.auth.dto.TokenDto;
import com.oauth2.login.global.security.auth.dto.LoginDto;
import com.oauth2.login.global.security.auth.jwt.TokenProvider;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import com.oauth2.login.global.security.auth.utils.Responder;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;

    private final RedisDao redisDao;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, TokenProvider tokenProvider, RedisDao redisDao) {
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
        this.redisDao = redisDao;
    }

    /*
     * Spring Security의 인증처리에서 토큰 생성부분을 가로채서 만듬.
     * 인증 위임을 해당 메서드가 오버라이딩해서 대신 객체를 전달해줌
     * */
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        ObjectMapper objectMapper = new ObjectMapper();

        LoginDto loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class); // ServletInputSteam을 LoginDto 클래스 객체로 역직렬화 (즉, JSON 객체꺼냄)
         log.info("# attemptAuthentication : loginDto.getEmail={}, login.getPassword={}",loginDto.getEmail(),loginDto.getPassword());

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws ServletException, IOException {

        AuthMember authMember = (AuthMember) authResult.getPrincipal();
        TokenDto tokenDto = tokenProvider.generateTokenDto(authMember);
        String grantType = tokenDto.getGrantType(); // Bearer
        String accessToken = tokenDto.getAccessToken(); // accessToken 만들기
        String refreshToken = tokenDto.getRefreshToken(); // refreshToken 만들기

        String headerValue = grantType + " " + accessToken;
        response.setHeader("Authorization",headerValue);
        response.setHeader("Refresh",refreshToken);

        Responder.loginSuccessResponse(response,authMember); // login 완료시 Response 응답 만들기

        // Refresh Token Redis 저장 ( key = Email / value = Refresh Token
        int refreshTokenExpirationMinutes = tokenProvider.getRefreshTokenExpirationMinutes();
        redisDao.setValues(authMember.getEmail(),refreshToken, Duration.ofMinutes(refreshTokenExpirationMinutes));


        // RefreshToken Cookie로 담는 방법
//        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
//                .maxAge(7 * 24 * 60 * 60)
//                .path("/")
//                .secure(true)
//                .sameSite("None")
//                .httpOnly(true)
//                .build();
//        response.setHeader("Set-Cookie", cookie.toString());

        log.info("# accessToken = {}",headerValue);
        log.info("# refreshToken = {}",refreshToken);

        this.getSuccessHandler().onAuthenticationSuccess(request,response,authResult);
    }
}
