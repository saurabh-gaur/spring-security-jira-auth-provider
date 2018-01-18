package com.jira.authentication

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority

import com.jira.command.JwtRequest
import com.jira.domain.JiraConnectInfo
import com.jira.verify.IJiraRequestVerifier

/**
 * @author Saurabh
 */
class JiraAuthenticationProvider implements AuthenticationProvider {

	IJiraRequestVerifier jiraRequestVerifier

	@Override
	public Authentication authenticate(Authentication auth) {
		JiraAuthenticationToken jiraAuthenticationToken = (JiraAuthenticationToken)auth
		JwtRequest jwtRequest = jiraAuthenticationToken.jwtRequest

		JiraConnectInfo.withTransaction { status ->

			if(auth && jwtRequest) {

				//Now verify request
				JiraConnectInfo jiraConnect = jiraRequestVerifier.verifyRequest(jwtRequest)

				if(!jiraConnect) {
					throw new InsufficientAuthenticationException("Could not authenticate request")
				}

				//Now set all authentication details
				jiraAuthenticationToken.authenticated = true
				jiraAuthenticationToken.credentials = jiraConnect.clientKey
				jiraAuthenticationToken.authorities = jiraConnect.authorities?.collect { new SimpleGrantedAuthority(it) }
				jiraAuthenticationToken.principal = jiraConnect.user
				jiraAuthenticationToken.details = new JiraDetails(
						applicationKey: jiraConnect.applicationKey,
						applicationName: jiraConnect.applicationName,
						description: jiraConnect.description,
						installed: jiraConnect.installed,
						uninstalled: jiraConnect.uninstalled,
						enabled: jiraConnect.enabled,
						disabled: jiraConnect.disabled)
			}
			
			return jiraAuthenticationToken
		}
	}

	@Override
	public boolean supports(Class authentication) {
		return JiraAuthenticationToken.class.isAssignableFrom(authentication)
	}

	public void setJiraRequestVerifier(IJiraRequestVerifier jiraRequestVerifier) {
		this.jiraRequestVerifier = jiraRequestVerifier
	}
}