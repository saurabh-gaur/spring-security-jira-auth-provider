package com.jira.extractor


/**
 * @author Saurabh
 */
public class JwtRequestExtractor implements IJwtRequestExtractor {

	/**
	 * @param request
	 */
	public String extractJwt(def request) {

		String jwt = request.getParameter("jwt")

		if (!jwt) {
			jwt = getJwtHeaderValue(request.getHeader("Authorization"))
		}
		return jwt
	}

	/**
	 * @param authHeader
	 * @return
	 */
	private String getJwtHeaderValue(String authHeader) {
		
		if(authHeader) {
			
			String first4Chars = authHeader.substring(0, Math.min(4, authHeader.length()))

			if ("JWT ".equalsIgnoreCase(first4Chars)) {
				return authHeader.substring(4);
			}
		}
		return null
	}
}

