package com.mavennet.album.exception;

public class AuthenticationException extends RuntimeException {

	private static final long serialVersionUID = 2958614748923549901L;

	public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
	
	public AuthenticationException(String message) {
        super(message);
    }
}
