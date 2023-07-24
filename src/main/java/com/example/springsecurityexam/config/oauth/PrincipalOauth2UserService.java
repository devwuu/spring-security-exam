package com.example.springsecurityexam.config.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    // oauth2 로그인 후 후처리를 해줍니다.
    // 구글로부터 받은 userRequest 데이터에 대한 후처리를 해주는 함수
    // 무슨 정보가 있냐면... -> 액세스토큰, 사용자 정보
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);// 이 함수를 타면 사용자 정보가 로드 됩니다.
        // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인을 완료 -> 로그인 code를 리턴 -> access token 리턴  <<-- OAuth2UserRequest
        // access token으로 사용자 정보 요청 -> 사용자 정보 리턴 받음 <<-- super.loadUser(userRequest)

        return oAuth2User;
    }
}
