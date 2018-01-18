package com.jira.domain

/**
 * @author Saurabh
 */
class JiraConnectInfo {

	String applicationKey
	String applicationName

	String clientKey
	String publicKey
	String sharedSecret
	String description

	//Integer tenantId
	def user

	Date dateCreated
	Date lastUpdated
	
	boolean installed
	boolean uninstalled
	boolean enabled
	boolean disabled
	

	static hasMany = [
		authorities: String
	]

	static mapping = {
		clientKey type: 'text'
		publicKey type: 'text'
		sharedSecret type: 'text'
		version false
	}

	static constraints = {
		applicationKey blank: false, unique: true
		applicationName nullable: true

		clientKey nullable: true
		publicKey nullable: true
		sharedSecret nullable:true
		description nullable:true

		authorities nullable: true
	}
}
