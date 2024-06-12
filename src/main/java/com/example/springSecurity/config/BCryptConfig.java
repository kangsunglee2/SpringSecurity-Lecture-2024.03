package com.example.springSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class BCryptConfig {

	@Bean
	public BCryptPasswordEncoder bCryptEncoder() {
		return new BCryptPasswordEncoder();
	}
	
}
// 패스워드 암호화 해주는 config