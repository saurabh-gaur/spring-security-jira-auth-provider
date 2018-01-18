package com.jira.extractor

/**
 * @author Saurabh
 */
public interface IJwtRequestExtractor {
	
	/**
	 * @param request
	 * @return
	 */
	public String extractJwt(def request)
	
}