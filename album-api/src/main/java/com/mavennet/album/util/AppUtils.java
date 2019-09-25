package com.mavennet.album.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;

import com.mavennet.album.auth.jwt.JwtUserDetails;

public class AppUtils {
	
	private static final Logger logger = LoggerFactory.getLogger(AppUtils.class);

	public static Long getLoggedInUserId() {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		Long userId = null;
		if (principal instanceof JwtUserDetails) {
			userId = ((JwtUserDetails) principal).getId();
			logger.debug("LoggedIn User --> " + ((JwtUserDetails) principal).getId());
		}
		return userId;
	}
}
