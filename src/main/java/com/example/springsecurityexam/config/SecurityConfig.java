package com.example.springsecurityexam.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록 됩니다
public class SecurityConfig {

    @Bean // 비밀번호 암호화
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean // 시큐리티 기본 설정, 인증 및 인가 설정
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(configurer -> configurer.disable())
            .authorizeHttpRequests(registry ->
                    registry.requestMatchers("/user/**").authenticated()
                            .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                            .requestMatchers("/admin/**").hasRole("ADMIN")
                            .anyRequest().permitAll())
            .formLogin(configurer -> configurer.loginPage("/login"));

                // requestMatchers : request 경로가 이쪽인 사람들은...
                // authenticated : 인증(로그인)된 사람만 들어올 수 있다.
                // hasAnyRole : 인증 뿐만 아니라 인가(권한)된 사람만 들어올 수 있다.
                // hasAnyRole : 인증 뿐만 아니라 인가(권한)된 사람만 들어올 수 있다.
                // anyRequest : 나머지 요청들은 인증/인가 설정이 없음

        return http.build();
    }


}
