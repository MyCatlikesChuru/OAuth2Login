package com.oauth2.login.global.security.auth.oauth;

import com.oauth2.login.domain.member.entity.Member;
import com.oauth2.login.domain.member.repository.MemberRepository;
import com.oauth2.login.global.security.auth.utils.CustomAuthorityUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class OAuthService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final MemberRepository memberRepository;
    private final CustomAuthorityUtils customAuthorityUtils;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest); // OAuth 서비스에서 가져온 유저 정보를 담고있음

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // OAuth 서비스 이름(ex. kakao, github, naver, google)

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName(); // OAuth 로그인 시 키(pk)가 되는 값
        Map<String, Object> attributes = oAuth2User.getAttributes(); // OAuth 서비스의 유저 정보들

        log.info("# registrationId = {}", registrationId);
        log.info("# userNameAttributeName = {}", userNameAttributeName);
        log.info("# attributes = {}", attributes.toString());


//        Map<String, Object> att = OAuthAttributes.sameGetAttributes(registrationId, attributes);

        OAuthUserProfile oAuthUserProfile = OAuthAttributes.extract(registrationId, attributes); // registrationId에 따라 유저 정보를 통해 공통된 UserProfile 객체로 만들어 줌

        log.info("# oAuthUserProfile.getEmail = {}", oAuthUserProfile.getEmail());
        log.info("# oAuthUserProfile.getName = {}", oAuthUserProfile.getName());
        log.info("# oAuthUserProfile.getOauthId = {}", oAuthUserProfile.getOauthId());


        List<String> roles = customAuthorityUtils.getAuthrities("USER");
        List<GrantedAuthority> authorities = customAuthorityUtils.createAuthorities(roles);

        saveOrUpdate(oAuthUserProfile, roles); // DB에 권한과 정보 저장 (권한은 1:N 테이블로 설계)

        log.info("# OAuth2 DB 저장완료 ");


        return new DefaultOAuth2User(authorities, attributes, userNameAttributeName);
    }

    // oauth 이메일(아이디)로 회원가입 전 중복체크하고 oauth 계정에서 닉네임 등 변동 있을시 업데이트
    private Member saveOrUpdate(OAuthUserProfile userProfile, List<String> roles) {
        Member member = memberRepository.findByEmail(userProfile.getEmail())
                .map(m -> m.oauthUpdate(userProfile.getName(), userProfile.getEmail(), roles)) // OAuth 서비스 사이트에서 유저 정보 변경이 있을 수 있기 때문에 우리 DB에도 update
                .orElse(userProfile.createOauth2Member(roles));

        return memberRepository.save(member);
    }
}