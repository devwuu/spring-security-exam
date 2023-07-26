package com.example.springsecurityexam.filter;

import com.example.springsecurityexam.auth.UserPrincipal;
import com.example.springsecurityexam.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

// UsernamePasswordAuthenticationFilter 를 상속받아서
// security filter chain에 넣어주면
// 기존에 spring security에서 동작하던 UsernamePasswordAuthenticationFilter 대신에
// 이 친구가 돌아가게 됩니다.

// spring security의 기본 설정은 form login을 사용하고 /login으로 로그인 요청이 오면
// security 가 기본으로 가지고 있는 UsernamePasswordAuthenticationFilter가 동작하는 거였습니다.
// 하지만 우리는 form을 안 쓸거기 때문에 form login을 disable 해주고 새로운 필터를 구현합니다.
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private final AuthenticationManager authenticationManager;

    // 로그인 요청을 하면 로그인 시도를 위해 시행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.username(), user.password());

            // token을 만들어서 넘겨주면 spring security가 principalService 로직을 실행시켜줍니다.
            // principalService에 있는 loadUserByUsername 가 실행됩니다.
            // loadUserByUsername 안에 있는 로그인 시도를 해주고
            // 정상적으로 로그인된 사람이라면 로그인한 사람 정보를 돌려줍니다
            Authentication authentication = authenticationManager.authenticate(token);

            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            log.info("userPrincipal :::: {}", userPrincipal.toString());

            // 여기서 return된 Authentication은 spring security의 session 영역에 저장됩니다.
            // JWT를 사용하면서 세션을 굳이 사용할 필요는 없지만 권한 관리를 위해서 session에 넣어줍니다.
            // --> config에 맵핑해둔 권한별 접근 제어 때문에 넣어주는 거 같은데 그럼 만약 세션이 떨어진다고 하면
            // 그땐 사용자가 가지고 있는 토큰을 검증해서 붙이는건가?
            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    // attemptAuthentication 이 정상적으로 종료가 되면 실행되는 함수
    // 여기서 로그인된 사용자의 jwt 토큰을 발급/응답해주면 됩니다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
