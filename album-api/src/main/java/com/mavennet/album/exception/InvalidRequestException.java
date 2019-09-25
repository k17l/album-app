package com.mavennet.album.exception;

public class InvalidRequestException extends RuntimeException {
	
	private static final long serialVersionUID = 4954088547339425803L;
	
	public InvalidRequestException(String message, Throwable cause) {
        super(message, cause);
    }

	public InvalidRequestException(String message) {
        super(message);
    }
}
