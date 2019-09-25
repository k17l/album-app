package com.mavennet.album.auth.jwt.payload;

import lombok.Data;

@Data
public class JwtTokenRequest {

	private String username;
    private String password;
}
