package com.mavennet.album.auth.jwt;

import static com.mavennet.album.util.AppConstants.AUTHORIZATION_HEADER;
import static com.mavennet.album.util.AppConstants.BEARER;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mavennet.album.exception.InvalidJWTTokenException;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtOncePerRequestFilter extends OncePerRequestFilter{
	
	private static final Logger logger = LoggerFactory.getLogger(JwtOncePerRequestFilter.class);
	
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	
	@Autowired
	private JwtUserDetailsService jwtUserDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException, InvalidJWTTokenException {
		
		logger.debug("Authentication Request For URL --> " + request.getRequestURL());
		
		final String requestTokenHeader = request.getHeader(AUTHORIZATION_HEADER);
		
		String username = null;
        String jwtToken = null;
        
        
        // Get Username from JWT Token if Token exists else throw warning
        if (requestTokenHeader != null && requestTokenHeader.startsWith(BEARER)) {
        	jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUserNameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                logger.error("Invalid JWT Token Unable to get Username", e);
            } catch (ExpiredJwtException e) {
                logger.warn("JWT Token Expired, Please try with new Token", e);
            }
        } else {
            logger.warn("JWT Token Does not start with Bearer String");
        }
        
        logger.debug("Username from Token --> " + username);
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        	UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);
        	
        	 if (jwtTokenUtil.validateToken(jwtToken)) {
                 UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                 usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                 SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
             }
        }
        
        filterChain.doFilter(request, response);
	}
}