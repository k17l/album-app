package com.mavennet.album.auth.jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.mavennet.album.entity.User;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;

@AllArgsConstructor
@EqualsAndHashCode
public class JwtUserDetails implements UserDetails {
	
	private static final long serialVersionUID = 671624950389429963L;
	
	private static final Logger logger = LoggerFactory.getLogger(JwtUserDetails.class);

	private Long id;
	private String name;
	private String username;
	private String password;
	private Collection<? extends GrantedAuthority> authorities;	
	
	public static JwtUserDetails create(User user) {
		logger.debug("User Principal --> " + user);
		
		String role = "ROLE_USER";
		logger.debug("User Role :" + role);
		
		List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
	    authorities.add(new SimpleGrantedAuthority(role));
		return new JwtUserDetails(user.getId(), user.getName(), user.getUsername(), user.getPassword(),authorities);
	}	
	
	public Long getId() {
		return id;
	}
	
	public String getName() {
		return name;
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
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
}