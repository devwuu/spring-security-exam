package com.example.springsecurityexam.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.IOException;

@Slf4j
public class JwtFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        if(httpServletRequest.getMethod().equals("POST")){
            String authorization = httpServletRequest.getHeader("Authorization");
            log.info("authorization :::: {}", authorization);
            if(authorization.equals("token")){
                // jwt를 이용하게 되면 값이 아니라 그 토큰이 내가 발급한 토큰이 맞는지만 검증하면 된다.
                // 토큰은 정상적인 로그인이 완료 됐을 때만 발급해주면 된다.
                chain.doFilter(httpServletRequest, httpServletResponse);
            }else{
                throw new IllegalStateException("invalid token");
            }
        }
    }

}
