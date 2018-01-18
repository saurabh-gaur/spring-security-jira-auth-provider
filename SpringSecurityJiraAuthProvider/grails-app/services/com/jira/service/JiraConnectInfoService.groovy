package com.jira.service

import grails.transaction.Transactional

import com.jira.domain.JiraConnectInfo

/**
 * @author Saurabh
 */
@Transactional
class JiraConnectInfoService implements IJiraConnectInfoService {


	public JiraConnectInfo loadByApplicationKey(String applicationKey) {
		return JiraConnectInfo.findByApplicationKey(applicationKey)
	}

	public JiraConnectInfo updateJiraConnectInfo(JiraConnectInfo jiraConnectInfo) {
		return jiraConnectInfo.save(flush:true, failOnError: true)
	}

	public JiraConnectInfo loadByClientKey(String clientKey) {
		return JiraConnectInfo.findByClientKey(clientKey)
	}
}
