package com.example.springsecurityexam.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.springsecurityexam.auth.UserPrincipal;
import com.example.springsecurityexam.entity.User;
import com.example.springsecurityexam.repository.UserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Optional;

// security가 가지고 있는 filter 중에 BasicAuthenticationFilter 이라는 필터는
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 타게 돼있다.
// 권한이나 인증이 필요한 주소가 아니라면 타지 않는다.
// 이 필터를 상속 받아서 새로운 AuthenticationFilter 필터를 만들고
// 필터 체인에 걸어주면 BasicAuthenticationFilter 대신 여기를 타게 될 것입니다
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository repository;


    // 인증이나 권한이 필요한 api 요청이 있을 때 이 필터를 타게 됩니다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader("Authorization");
        // 요청 헤더에서 받아온 토큰을 검증해서 정상적인 사용자인지 검증합니다

        if(ObjectUtils.isEmpty(header) || ! header.startsWith("Bearer ")){
            chain.doFilter(request, response);
            return; // filter를 마저 탄 뒤에 이하 진행 불가하도록 return
        }
        String token = StringUtils.delete(header, "Bearer ");
        String username = JWT.require(Algorithm.HMAC512("test"))
                .build()
                .verify(token).
                getClaim("username")
                .asString();

        if(!ObjectUtils.isEmpty(username)){
            Optional<User> find = repository.findByUsername(username);
            // user가 정상적으로 조회되면 정상적인 유저라고 본다.
            if(find.isPresent()){
                UserPrincipal userPrincipal = new UserPrincipal(find.get());
                // jwt 토큰 서명이 정상이면 강제로 로그인 처리
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());
                // security session에 접근하여 Authentication 객체를 저장해준다
                // 강제로 로그인 처리
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                chain.doFilter(request, response);
            }
        }

    }

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
                                  UserRepository repository) {
        super(authenticationManager);
        this.repository = repository;
    }

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint) {
        super(authenticationManager, authenticationEntryPoint);
    }
}
