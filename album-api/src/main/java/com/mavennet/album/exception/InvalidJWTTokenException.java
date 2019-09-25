package com.mavennet.album.exception;

public class InvalidJWTTokenException extends RuntimeException {

	private static final long serialVersionUID = -4941505517926078264L;
	
	public InvalidJWTTokenException(String message, Throwable cause) {
        super(message, cause);
    }

	public InvalidJWTTokenException(String message) {
        super(message);
    }
	

}
