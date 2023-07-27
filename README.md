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

<br/>

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
