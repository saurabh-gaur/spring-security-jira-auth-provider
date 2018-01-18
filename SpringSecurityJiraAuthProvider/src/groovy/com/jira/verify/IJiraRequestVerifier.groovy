package com.jira.verify;

import com.jira.command.JwtRequest
import com.jira.domain.JiraConnectInfo


/**
 * @author Saurabh
 */
public interface IJiraRequestVerifier {

	/**
	 * @param jwtRequest
	 * @return
	 */
	public JiraConnectInfo verifyRequest(JwtRequest jwtRequest)
}
