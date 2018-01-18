package com.jira.extractor

import javax.servlet.http.HttpServletRequest

/**
 * @author Saurabh
 */
class JiraQueryExtractor {


	/**
	 * @param s
	 * @return
	 */
	private String urlEncodeUTF8(String s) {
		return URLEncoder.encode(s, "UTF-8")
	}

	/**
	 * @param map
	 * @return
	 */
	private String urlEncodeUTF8(Map<?,?> map) {

		StringBuilder sb = new StringBuilder()

		for (Map.Entry<?,?> entry : map.entrySet()) {

			if (sb.length() > 0) {
				sb.append("&")
			}

			sb.append(String.format("%s=%s",
					urlEncodeUTF8(entry.getKey().toString()),
					urlEncodeUTF8(entry.getValue().toString())))
		}
		return sb.toString()
	}


	/**
	 * It will extract query parameter from request
	 * then it will convert parameter Map<String,String[]> to Map<String,String>
	 * where value would be in csv if multiple then it will sort by its key
	 * 
	 * it will prepare for query string as same as JIRA required for authentication
	 * For mor details follow this link
	 * https://developer.atlassian.com/cloud/jira/platform/understanding-jwt/#a-name-creating-token-a-creating-a-jwt-token
	 * 
	 * @param request
	 * @return
	 */
	public String extractQueryString(HttpServletRequest request) {

		String queryString = ""

		Map parameterMap = request.getParameterMap()

		if(parameterMap) {
			Map queryMap = parameterMap.collectEntries { [(it.key):it.value.join(',')]  }?.sort { it.key }
			//Now remove jwt from map if exists
			queryMap.remove('jwt')

			//Now convert into query string
			queryString = urlEncodeUTF8(queryMap)
		}
		return queryString
	}
}
