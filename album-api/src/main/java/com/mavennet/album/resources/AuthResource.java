package com.mavennet.album.resources;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.mavennet.album.auth.jwt.JwtTokenUtil;
import com.mavennet.album.auth.jwt.payload.JwtTokenRequest;
import com.mavennet.album.auth.jwt.payload.JwtTokenResponse;
import com.mavennet.album.exception.AuthenticationException;


@RestController
public class AuthResource {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtTokenRequest authenticationRequest) throws AuthenticationException {
		Authentication authentication = authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
		SecurityContextHolder.getContext().setAuthentication(authentication);
		final String token = jwtTokenUtil.generateToken(authentication);
		return ResponseEntity.ok(new JwtTokenResponse(token));
	}
	
	private Authentication authenticate(String username, String password) {
	    Objects.requireNonNull(username);
	    Objects.requireNonNull(password);

	    try {
	      return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
	    } catch (BadCredentialsException bcEx) {
	      throw new AuthenticationException("INVALID_CREDENTIALS", bcEx);
	    }
	  }
}
