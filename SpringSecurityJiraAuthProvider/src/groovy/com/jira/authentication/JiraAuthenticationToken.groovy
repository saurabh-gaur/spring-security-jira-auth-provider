package com.jira.authentication

import org.springframework.security.core.Authentication
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.core.GrantedAuthority

import com.jira.command.JwtRequest

/**
 * @author Saurabh
 */
public class JiraAuthenticationToken implements Authentication, CredentialsContainer {

	Collection<? extends GrantedAuthority> authorities
	
	// clientKey
	Object credentials
	JiraDetails details
	Object principal


	boolean authenticated
	
	JwtRequest jwtRequest

	@Override
	public void eraseCredentials() {
		// TODO Auto-generated method stub
	}

	@Override
	public String getName() {
		return null;
	}
}