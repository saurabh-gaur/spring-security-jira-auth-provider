import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils

import com.jira.authentication.JiraAuthenticationProvider
import com.jira.filter.JiraAuthenticationFilter
import com.jira.service.JiraConnectInfoService
import com.jira.verify.JwtRequestVerifier

class SpringSecurityJiraAuthProviderGrailsPlugin {
	// the plugin version
	def version = "1.0"
	// the version or versions of Grails the plugin is designed for
	def grailsVersion = "2.5 > *"
	// resources that are excluded from plugin packaging
	def pluginExcludes = [
		"grails-app/views/error.gsp"
	]

	def loadAfter = ["springSecurityCore"]

	// TODO Fill in these fields
	def title = "Spring security jira auth provider" // Headline display name of the plugin
	def author = "Saurab Gaur"
	def authorEmail = "saurabh.gaur@bqurious.com"
	def description = '''This plugin is use to provide authentication for incoming call from JIRA to access the local resources to 
show on jira. It helps to setup our environment into JIRA as addon plugin.'''

	// URL to the plugin's documentation
	def documentation = "http://grails.org/plugin/grails-jira-jwt-auth"

	// Extra (optional) plugin metadata

	// License: one of 'APACHE', 'GPL2', 'GPL3'
	//    def license = "APACHE"

	// Details of company behind the plugin (if there is one)
	//    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

	// Any additional developers beyond the author specified above.
	//    def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

	// Location of the plugin's issue tracker.
	//    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

	// Online location of the plugin's browseable source code.
	//    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

	def doWithWebDescriptor = { xml ->
		// TODO Implement additions to web.xml (optional), this event occurs before
	}

	def doWithSpring = {

		def conf = SpringSecurityUtils.securityConfig

		if (!conf || !conf.active) {
			return
		}

		println 'Configuring Spring Security Jira Auth Provider ...'

		SpringSecurityUtils.loadSecondaryConfig 'DefaultGrailsJiraJwtAuthConfig'
		// have to get again after overlaying DefaultGrailsJiraJwtAuthConfig
		conf = SpringSecurityUtils.securityConfig

		jiraConnectInfoService(JiraConnectInfoService)

		jwtRequestVerifier(JwtRequestVerifier) { jiraConnectInfoService = ref('jiraConnectInfoService') }

		jiraAuthenticationProvider(JiraAuthenticationProvider) {
			jiraRequestVerifier = ref('jwtRequestVerifier')

		}

		jiraInstallationFilter(JiraAuthenticationFilter) {
			authenticationManager = ref("authenticationManager")
			authenticationFailureHandler = ref('authenticationFailureHandler')
			jiraInstallationEndPointUrl = conf.jira.lifecycle.installed
			jiraRequestUriMatcher = conf.jira.requestUriMatcher
		}

		SpringSecurityUtils.registerFilter  'jiraInstallationFilter', SecurityFilterPosition.LOGOUT_FILTER.order + 1

		println "... done configuring Spring Security Jira Auth Provider"
	}

	def doWithDynamicMethods = { ctx ->
		// TODO Implement registering dynamic methods to classes (optional)
	}

	def doWithApplicationContext = { ctx ->
		// TODO Implement post initialization spring config (optional)
	}

	def onChange = { event ->
		// TODO Implement code that is executed when any artefact that this plugin is
		// watching is modified and reloaded. The event contains: event.source,
		// event.application, event.manager, event.ctx, and event.plugin.
	}

	def onConfigChange = { event ->
		// TODO Implement code that is executed when the project configuration changes.
		// The event is the same as for 'onChange'.
	}

	def onShutdown = { event ->
		// TODO Implement code that is executed when the application shuts down (optional)
	}
}
