package com.jira.service

import com.jira.command.JwtRequest;
import com.jira.domain.JiraConnectInfo


/**
 * @author Saurabh
 */
public interface IJiraConnectInfoService {

	/**
	 * @param clientKey
	 * @return
	 */
	public JiraConnectInfo loadByClientKey(String clientKey)

	/**
	 * @param applicationKey
	 * @return
	 */
	public JiraConnectInfo loadByApplicationKey(String applicationKey)

	/**
	 * @param jiraConnectInfo
	 * @return
	 */
	public JiraConnectInfo updateJiraConnectInfo(JiraConnectInfo jiraConnectInfo)
}