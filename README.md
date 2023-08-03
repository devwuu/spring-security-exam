# Spring security 예제
* 강의 : 최주호님의 스프링부트 시큐리티 & JWT 강의 ( https://inf.run/R1AW )
* 사용 버전
  * spring boot ***(3.1.1)***
  * spring boot oauth2 client(3.1.1)
  * spring security ***(6.1.x)***
  * spring data JPA
  * mySql

<br/>

## (Spring boot 3.X + Spring Security 6.X) 변경사항

### 1. SecurityFilterChain 설정 방법 변경
* 람다를 사용해서 설정합니다.
* 출처: https://docs.spring.io/spring-security/reference/migration-7/configuration.html
* 출처 : https://docs.spring.io/spring-security/reference/reactive/integrations/cors.html

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/blog/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(formLogin -> formLogin
                .loginPage("/login")
                .permitAll()
            )
            .rememberMe(Customizer.withDefaults());

        return http.build();
    }
}
```

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
	CorsConfiguration configuration = new CorsConfiguration();
	configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
	configuration.setAllowedMethods(Arrays.asList("GET","POST"));
	UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	source.registerCorsConfiguration("/**", configuration);
	return source;
}

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .cors(configurer ->
                configurer.configurationSource(corsConfigurationSource())
        )
        ...

    return http.build();
}
```

<br/>

### 2. AuthenticationManager 등록 방법
* Bean을 등록해서 사용합니다
* 출처 : https://stackoverflow.com/questions/74877743/spring-security-6-0-dao-authentication

```java
@Bean
public AuthenticationManager authenticationManager(){
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailService);
    authProvider.setPasswordEncoder(getPassWordEncoder());
    return new ProviderManager(authProvider);
}
```

<br/>

## Further Study 

### 1. 여러개의 SecurityFilterChain 등록하는 방법
* securityMatchers 함수를 사용합니다
* 예제 : https://github.com/devwuu/vet_2023
* 출처 : https://docs.spring.io/spring-security/reference/5.8/migration/servlet/config.html#use-new-security-matchers
* 출처 : https://www.danvega.dev/blog/2023/04/20/multiple-spring-security-configs/

```java

    @Bean
    public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatchers((matchers) -> matchers
                        .requestMatchers("client/**", "v1/client/**")
                )
		...

        return http.build();
    }

    @Bean
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatchers((matchers) -> matchers
                        .requestMatchers("admin/**", "v1/admin/**")
                )
		...

        return http.build();
    }

```

<br/>

### 2. login url을 custom 하는 법
* 로그인을 담당하는 filter에 url을 맵핑시켜준다
* 예제 : https://github.com/devwuu/vet_2023
* 출처 : https://stackoverflow.com/questions/49583373/how-to-change-login-url-in-spring-security

```java

   @Bean
    public AdminAuthenticationFilter adminAuthenticationFilter(){
	...
        adminAuthenticationFilter.setFilterProcessesUrl("/admin/token");
        adminAuthenticationFilter.setPostOnly(true);
        return adminAuthenticationFilter;
    }

```

<br/>

### 3. AuthorizationFilter에서 사용하지 않는 authenticationManager를 제외하고 Filter를 구현하는 방법
* OncePerRequestFilter 를 상속받는다
* 이 경우엔 Filter를 등록할 때 Filter의 순서를 정해줘야한다
* 예제 : https://github.com/devwuu/vet_2023
* 출처 : https://www.toptal.com/spring/spring-security-tutorial

```java

package com.web.vt.security;

import com.auth0.jwt.JWT;
import com.web.vt.utils.StringUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AdminAuthorizationFilter extends OncePerRequestFilter {

    private final AdminDetailService adminDetailService;

    public AdminAuthorizationFilter(AdminDetailService adminDetailService) {
        this.adminDetailService = adminDetailService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        if(StringUtil.isEmpty(authorization) || !StringUtil.startsWith(authorization, JwtProperties.PRE_FIX)){
            filterChain.doFilter(request, response);
            return;
        }

        String id = JWT.require(JwtProperties.SIGN)
                .build()
                .verify(StringUtil.remove(authorization, JwtProperties.PRE_FIX))
                .getClaim("id")
                .asString();

        AdminPrincipal principal = (AdminPrincipal) adminDetailService.loadUserByUsername(id);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(request, response);
    }

}

```

```java

    @Bean
    public AdminAuthorizationFilter adminAuthorizationFilter(){
        return new AdminAuthorizationFilter(adminDetailService());
    }

    @Bean
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
		...
                .addFilter(adminAuthenticationFilter())
                .addFilterBefore(adminAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

```

<br/>

## local에서 CORS 설정 테스트하기

### 테스트용 스크립트
* terminal을 사용합니다
* 출처: https://beanbroker.github.io/2019/12/01/etc/cors_curl

```shell
curl -I -X OPTIONS \
  -H "Origin: http://localhost:8090" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/home
```

<br/>

### 결과 예시

```shell
curl -I -X OPTIONS \
  -H "Origin: http://localhost:8999" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/home
HTTP/1.1 403
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Transfer-Encoding: chunked
Date: Tue, 25 Jul 2023 07:30:00 GMT
```
```shell
curl -I -X OPTIONS \
  -H "Origin: http://localhost:8090" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/home
HTTP/1.1 200
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Access-Control-Allow-Origin: http://localhost:8090
Access-Control-Allow-Methods: GET
Access-Control-Allow-Credentials: true
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Length: 0
Date: Tue, 25 Jul 2023 07:30:04 GMT
```
