package com.example.springSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.example.springSecurity.Service.MyOAuth2UserService;

import jakarta.servlet.DispatcherType;


@Configuration
@EnableWebSecurity	
public class SecurityConfig {
	@Autowired private MyOAuth2UserService myOAuth2UserService;

	@Bean	// @Bean 주입되기 위해 사용
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(auth -> auth.disable())		// 괄호 안에 람다함수를 사용해야 함
			.headers(x -> x.frameOptions(y -> y.disable()))		// CK Editor image upload 때 필요
			.authorizeHttpRequests(auth -> auth
					.dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
					.requestMatchers("user/register",	// 로그인 없이 사용할수있는 목록
							"/img/**", "/css/**", "/js/**", "/error/**").permitAll()	//** 모든것들
					.requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")	// 어드민만 사용할수있는 목록
					.anyRequest().authenticated()
			)
			.formLogin(auth -> auth
					.loginPage("/user/login") 			// 로그인 폼
					.loginProcessingUrl("/user/login") 	// 스프링 시큐리티가 낚아 챔. UserDetailsService 구현객체에서 처리해주어야 함
					.usernameParameter("uid")
					.passwordParameter("pwd")
					.defaultSuccessUrl("/user/loginSuccess", true) 		// 내가 로그인후 해야할 일, 예) 세션 세팅, 오늘의 메세지 등
					.permitAll()
			)
			.oauth2Login(auth -> auth
					.loginPage("/user/login")
					// 소셜 로그인이 완료된 이후의 후처리
					// 1. 코드받기(인증), 2. 액세스 토큰(권한), 3. 사용자 프로필 정보를 가져옴
					// 4. 3에서 받은 정보를 토대로 DB에 없으면 가입을 시켜줌
					// 5. 프로바이더가 제공하는 정보 + 추가정보 수집 (주소, ...)
					.userInfoEndpoint(user -> user.userService(myOAuth2UserService))
					.defaultSuccessUrl("/user/loginSuccess", true)
			)
			.logout(auth -> auth
					.logoutUrl("/user/logout")		// 로그아웃으로 이동
					.invalidateHttpSession(true) 	// 로그아웃시 세션 초기화
					.deleteCookies("JSESSIONID") 	// 로그아웃시 쿠키 삭제
					.logoutSuccessUrl("/user/login")// 로그아웃이 끝나고 로그인 페이지로 이동
			);
		
		return http.build();
	}
	
}
// 실전에서 응요할때 사용하는 식