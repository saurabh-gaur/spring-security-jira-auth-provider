package com.jira.filter

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.web.filter.GenericFilterBean

import com.jira.authentication.JiraAuthenticationToken
import com.jira.command.JwtRequest
import com.jira.extractor.IJwtRequestExtractor
import com.jira.extractor.JiraQueryExtractor
import com.jira.extractor.JwtRequestExtractor

/**
 * @author Saurabh
 */
public class JiraAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

	AuthenticationManager authenticationManager
	AuthenticationFailureHandler authenticationFailureHandler
	ApplicationEventPublisher applicationEventPublisher
	IJwtRequestExtractor jwtRequestExtractor = new JwtRequestExtractor()
	JiraQueryExtractor jiraQueryExtractor = new JiraQueryExtractor()

	String jiraInstallationEndPointUrl = ""
	String jiraRequestUriMatcher = ""


	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

		final HttpServletRequest request = (HttpServletRequest) req
		final HttpServletResponse response = (HttpServletResponse) res

		//Get the request path first path
		String path = request.getRequestURI().substring(request.getContextPath().length())

		//Check if request is specific for this filter then process with this filter
		//otherwise go ahead with other filter.
		if (!path.startsWith(jiraRequestUriMatcher)) {

			if (logger.isDebugEnabled()) {
				logger.debug("It's  not a Jira request, skip this filter")
			}

			chain.doFilter(request, response)
			return
		}

		//This mean need to authenticate Jira request
		//Get previous authentication to reverse after stateless authentication
		Authentication previousAuthentication = SecurityContextHolder.getContext().getAuthentication()

		try {

			//Now extract JWT
			String jwt = jwtRequestExtractor.extractJwt(request)
			//Now extract query string
			String queryString = jiraQueryExtractor.extractQueryString(request)
			//Now get request method
			String method = request.getMethod()

			//Now build JWT request object
			JwtRequest jwtRequest =  new JwtRequest(
					methodName:method,
					queryString:queryString,
					path:path,
					jwt:jwt)

			def requestObject

			if(method == "POST") {
				//Get data from body
				requestObject = request.JSON
			}

			//Before authentication store details into DB if it is installation request
			if ((path == jiraInstallationEndPointUrl) && (requestObject)) {
				//Prepare add client details in request
				jwtRequest.clientKey = requestObject.clientKey
				jwtRequest.applicationKey = requestObject.key
				jwtRequest.publicKey = requestObject.publicKey
				jwtRequest.sharedSecret = requestObject.sharedSecret
				jwtRequest.description = requestObject.description
				jwtRequest.isInstallation = true
			}

			//Now prepare authentication
			Authentication auth = authenticationManager.authenticate(new JiraAuthenticationToken(jwtRequest:jwtRequest, authenticated:false))

			if(!auth.authenticated) {
				unsuccessfulAuthentication((HttpServletRequest) request, response, new BadCredentialsException("Authorization Header does not Match"))
				return
			}

			//Now set this into context
			SecurityContextHolder.getContext().setAuthentication(auth)

			if (logger.isDebugEnabled()) {
				logger.debug("Authentication success")
			}

			chain.doFilter(request, response)

		}catch(InsufficientAuthenticationException e) {
			logger.warn("Could not authenticate request", e)
			unsuccessfulAuthentication((HttpServletRequest) request, response, e)
		}catch(Exception e) {
			logger.warn("General error occurred", e)
			unsuccessfulAuthentication((HttpServletRequest) request, response, new InsufficientAuthenticationException(e.message))
		}finally {
			if (logger.isDebugEnabled()) {
				logger.debug("Processed request using Jira authentication, not clear it and resume with prevous authetication")
			}
			SecurityContextHolder.getContext().setAuthentication(previousAuthentication)
		}
	}

	/**
	 * @param request
	 * @param response
	 * @param exception
	 * @throws IOException
	 * @throws ServletException
	 */
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		SecurityContextHolder.clearContext()
		authenticationFailureHandler.onAuthenticationFailure(request, response, exception)
	}

	/**
	 * @param jiraInstallationEndPointUrl
	 */
	public void setJiraInstallationEndPointUrl(String jiraInstallationEndPointUrl) {
		this.jiraInstallationEndPointUrl = jiraInstallationEndPointUrl
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher
	}
}