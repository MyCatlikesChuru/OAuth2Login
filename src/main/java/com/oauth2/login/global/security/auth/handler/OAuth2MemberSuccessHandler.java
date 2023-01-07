package com.oauth2.login.global.security.auth.handler;


import com.oauth2.login.domain.member.repository.MemberRepository;
import com.oauth2.login.global.security.auth.dto.TokenDto;
import com.oauth2.login.global.security.auth.jwt.TokenProvider;
import com.oauth2.login.global.security.auth.oauth.OAuthService;
import com.oauth2.login.global.security.auth.oauth.OAuthUserProfile;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Map;


@Slf4j
@AllArgsConstructor
public class OAuth2MemberSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final TokenProvider tokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authResult) throws IOException, ServletException {

        log.info("# Redirect to Frontend");

        DefaultOAuth2User ss = (DefaultOAuth2User) authResult.getPrincipal();
        Map<String, Object> attributes = ss.getAttributes();
        log.info(attributes.toString());
        log.info("# 타입 캐스팅 문제없음1");
        AuthMember authMember = (AuthMember) authResult.getPrincipal();
        TokenDto tokenDto = tokenProvider.generateTokenDto(authMember);
        String grantType = tokenDto.getGrantType(); // Bearer
        String accessToken = tokenDto.getAccessToken(); // accessToken 만들기
        String refreshToken = tokenDto.getRefreshToken(); // refreshToken 만들기

        log.info("# 타입 캐스팅 문제없음2");

        log.info("# accessToken = {}",accessToken);
        log.info("# refreshToken = {}",refreshToken);

        // 리다이렉트를 하기위한 정보들을 보내줌
        redirect(request,response,accessToken,refreshToken);
    }

    private void redirect(HttpServletRequest request,
                          HttpServletResponse response,
                          String accessToken,
                          String refreshToken) throws IOException {

        // 받은 정보를 토대로 AccessToken, Refresh Token을 만듬
        // Token을 토대로 URI를 만들어서 String으로 변환
        String uri = createURI(request, accessToken, refreshToken).toString();

        // 헤더에 전송해보기
        String headerValue = "Bearer "+ accessToken;
        response.setHeader("Authorization",headerValue); // Header에 등록
        response.setHeader("Refresh",refreshToken); // Header에 등록
        // response.setHeader("Access-Control-Allow-Credentials:", "true");
        // response.setHeader("Access-Control-Allow-Origin", "*");
        // response.setHeader("Access-Control-Expose-Headers", "Authorization");

        // 만든 URI로 리다이렉트 보냄
        getRedirectStrategy().sendRedirect(request,response,uri);
    }

    private URI createURI(HttpServletRequest request, String accessToken, String refreshToken){
        // 리다이렉트시 JWT를 URI로 보내는 방법
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("access_token", accessToken);
        queryParams.add("refresh_token", refreshToken);

        String serverName = request.getServerName();
        // log.info("# serverName = {}",serverName);

        return UriComponentsBuilder
                .newInstance()
                .scheme("http")
                .host(serverName)
                //.host("localhost")
                .port(80) // 기본 포트가 80이기 때문에 괜찮다
                .path("/token")
                .queryParams(queryParams)
                .build()
                .toUri();
    }
}
