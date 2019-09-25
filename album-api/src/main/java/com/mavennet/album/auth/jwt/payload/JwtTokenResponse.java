package com.mavennet.album.auth.jwt.payload;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class JwtTokenResponse {

	private String token;
}
