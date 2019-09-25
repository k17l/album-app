package com.mavennet.album.auth.jwt.payload;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class ErrorResponse {

	private Boolean successFlag;
	private String errorMessage;
}
