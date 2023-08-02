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
