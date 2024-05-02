package com.example.demo.config;

import com.example.demo.jwt.JwtAuthFilter;
import com.example.demo.jwt.JwtUtil;
import com.example.demo.security.UserRoleEnum;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SpringSecurityConfig {

    private final JwtUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // resources 자원 접근 허용
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /* csrf 설정 해제. */
        http.csrf().disable();

        /*JWT 사용 위해 기존의 세션 방식 인증 해제*/
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        /* URL Mapping */
        http.authorizeRequests()
                .requestMatchers(HttpMethod.GET, "/signup").permitAll()/*회원가입 페이지는 무조건 허용*/
                .requestMatchers(HttpMethod.GET, "/login").permitAll()/*로그인 페이지 허용.*/
                .requestMatchers(HttpMethod.POST, "/api/signup").permitAll()/*회원가입 요청은 무조건 허용*/
                .requestMatchers(HttpMethod.POST, "/api/login").permitAll()/*로그인 요청 허용*/
                .requestMatchers("/cookie/test").permitAll()
                .requestMatchers("/vip").hasRole(UserRoleEnum.VIP_MEMBER.toString())/*vip 멤버 전용 페이지*/
                .requestMatchers("/admin").hasRole(UserRoleEnum.ADMIN.toString())/*관리자 전용 페이지*/
                .anyRequest().authenticated()/*나머지 요청은 전부 인증되어야 함*/
                /*JwtAuthFilter에 jwtUtil을 전달하여 UsernamePasswordAuthenticationFilter전에 필터로 등록한다.*/
                .and().addFilterBefore(new JwtAuthFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);



        /*로그인 페이지를 /login으로 설정한다.
        1. 인증이 되지 않은 사용자가 permitAll()페이지가 아닌 페이지에 접근할 때 /login으로 강제 이동 시킨다.
        2. 이때의 인증은 위에 필터에 등록해 놓은 JWT 토큰의 유무(유효성 검증) 기준이다.*/
        http.formLogin().loginPage("/login");

        /*인가 (권한 인증) 실패 시 아래의 핸들러 작동 ex) 멤버인데 -> VIP 멤버의 페이지를 접근하는 경우*/
        http.exceptionHandling().accessDeniedPage("/forbidden");


        return http.build();
    }


}
