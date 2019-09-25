package com.mavennet.album.resources;

import java.util.Objects;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
import com.mavennet.album.auth.jwt.payload.ErrorResponse;
import com.mavennet.album.auth.jwt.payload.JwtTokenRequest;
import com.mavennet.album.auth.jwt.payload.JwtTokenResponse;
import com.mavennet.album.exception.AuthenticationException;
import com.mavennet.album.exception.InvalidJWTTokenException;
import com.mavennet.album.exception.InvalidRequestException;


@RestController
public class AuthResource {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@PostMapping("/authenticate")
	@SuppressWarnings(value = { "rawtypes","unchecked" })
	public ResponseEntity<?> createAuthenticationToken(@Valid @RequestBody JwtTokenRequest authenticationRequest) {
		try {
			if(!Objects.isNull(authenticationRequest) && !Objects.isNull(authenticationRequest.getUsername()) && !Objects.isNull(authenticationRequest.getPassword())) {
				Authentication authentication = authenticate(authenticationRequest.getUsername(),authenticationRequest.getPassword());
				SecurityContextHolder.getContext().setAuthentication(authentication);
				final String token = jwtTokenUtil.generateToken(authentication);
				return ResponseEntity.ok(new JwtTokenResponse(token));
			} else {
				throw new InvalidRequestException("Invalid Request Object, Please check the JSON Request");
			}
		}catch(InvalidJWTTokenException ex) {
			return new ResponseEntity(new ErrorResponse(false, ex.getMessage()), HttpStatus.BAD_REQUEST);
		}
		catch(Exception ex) {
			return new ResponseEntity(new ErrorResponse(false, ex.getMessage()), HttpStatus.BAD_REQUEST);
		}
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
