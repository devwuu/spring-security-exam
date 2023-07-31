package com.example.springsecurityexam.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    // security filter 가 실행된 다음에 custom filter가 실행됩니다.
    // 만약 security filter보다 먼저 실행되게 하고 싶으면 security filter에 before filter로 등록해줘야합니다.
    // spring security filter chain 순서 보고 원하는 순서에 끼워맞추면 됨.
    // FilterRegistrationBean 방식으로 등록해서는 security filter보다 먼저 수행되지 않음
//    @Bean
//    public FilterRegistrationBean<JwtFilter> jwtFilterFilterRegistration(){
//        FilterRegistrationBean<JwtFilter> filter = new FilterRegistrationBean<>(new JwtFilter());
//        filter.addUrlPatterns("/*");
//        filter.setOrder(0); // 낮은 번호가 우선순위를 가진다.
//        return filter;
//    }
}
