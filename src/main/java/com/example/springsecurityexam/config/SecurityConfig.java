package com.example.springsecurityexam.config;


import com.example.springsecurityexam.auth.PrincipalService;
import com.example.springsecurityexam.filter.JwtAuthenticationFilter;
import com.example.springsecurityexam.filter.JwtFilter;
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalService service;
    private final PasswordEncoder passwordEncoder;

    // authenticationManager를 bean으로 등록해줍니다
    @Bean
    public AuthenticationManager authenticationManager(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // DaoAuthenticationProvider 는 UserDetailService를 사용할 때 사용할 수 있는 AuthenticationProvider의 구현체입니다.

        authProvider.setUserDetailsService(service);
        authProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authProvider);
    }

    @Bean
    public UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        // 자격증명을 함께 요청할 것인지 여부를 결정한다.
        // request의 자격이 증명 되었을 때 client의 자바스크립트가 response에 접근 가능하게 할 것인지 말것인지를 결정한다.
        // true 일 때, 자격 증명이 안되면 reponse에 접근할 수 없다
        // false 일 때, 자격증명을 요청하지 않는다. --> 사용자 인증을 사용하지 않을거라면 false로 설정하는 것
        configuration.addAllowedOrigin("http://localhost:8090"); // 이곳에서 요청한 request에만 응답
        configuration.addAllowedHeader("*"); // 모든 헤더를 허용함
        configuration.addAllowedMethod("*"); // 모든 메서드(GET, PUT, DELETE, POST ...)를 허용함
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilterBefore(new JwtFilter(), AuthorizationFilter.class)
                .cors(configurer -> configurer.configurationSource(urlBasedCorsConfigurationSource()))
                // @CrossOrigin 은 인증이 필요 없을 때 사용하고 인증이 필요한 경우에는 security filter에 등록해줘야 합니다.
                .csrf(configurer -> configurer.disable())
                .sessionManagement(
                        configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        // 세션을 사용하지 않겠다.
                        // statelss 서버로 만들겠습니다.
                        // 원래 웹은 stateless 하지만 stateful처럼 사용하기 위해서 session 과 cookie를 사용한다
                        // 근데 이 세션을 사용하지 않겠다고 설정함으로써 sateless하게 사용한다고 말하는 것임
                )
                .formLogin(configurer -> configurer.disable()) // form태그를 이용해 login을 하지 않음 (jwt 토큰만 사용할 것이라서)
                .httpBasic(configurer -> configurer.disable()) // bearer 방식을 사용할거예요
                .authorizeHttpRequests(registry ->
                        registry.requestMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                                .anyRequest().permitAll()
                );

        return http.build();
    }

}
