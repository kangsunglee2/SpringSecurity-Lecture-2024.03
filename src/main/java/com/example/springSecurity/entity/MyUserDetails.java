package com.example.springSecurity.entity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import lombok.RequiredArgsConstructor;

// Spring Security가 로그인 POST 요청을 낚아채서 로그인을 진행시킴
// 로컬 로그인 - UserDerails 구현
// 소셜 로그인 - OAuth2User 구현

public class MyUserDetails implements UserDetails, OAuth2User {
	private SecurityUser securityUser;
	private Map<String, Object> attributes;
	
	public MyUserDetails() { }
	// 로컬 로그인 - 스프링이 생성자 방식으로 의존성 주입
	public MyUserDetails(SecurityUser securityUser) {
		this.securityUser = securityUser;
	}
	// 소셜 로그인 - 스프링이 생성자 방식으로 의존성 주입
	public MyUserDetails(SecurityUser securityUser, Map<String, Object> attributes) {
		this.securityUser = securityUser;
		this.attributes = attributes;
	}

	// 사용자의 권한을 리턴
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() { // GrantedAuthority를 상속받은 무언가든
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return securityUser.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return securityUser.getPwd();
	}

	@Override
	public String getUsername() {
		return securityUser.getUid();
	}

	@Override
	public boolean isAccountNonExpired() {
		if (securityUser.getIsDeleted() == 0) {
			return true;
		}
		return false;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public String getName() {
		return null;
	}
	
	public SecurityUser getSecurityUser() {
		return securityUser;
	}
}
