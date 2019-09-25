package com.mavennet.album.auth.jwt.payload;

import javax.validation.constraints.NotEmpty;

import lombok.Data;

@Data
public class JwtTokenRequest {

	@NotEmpty(message = "Please provide a username")
	private String username;
	
	@NotEmpty(message = "Please provide a username")
    private String password;
}
