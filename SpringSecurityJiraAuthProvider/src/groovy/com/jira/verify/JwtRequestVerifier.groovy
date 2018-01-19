package com.jira.verify

import static org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString
import static org.apache.commons.codec.binary.Hex.encodeHexString
import groovy.json.JsonSlurper

import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId

import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import org.springframework.security.authentication.InsufficientAuthenticationException

import com.jira.command.JwtClaims
import com.jira.command.JwtRequest
import com.jira.domain.JiraConnectInfo
import com.jira.service.IJiraConnectInfoService

/**
 * @author Saurabh
 */
public class JwtRequestVerifier implements IJiraRequestVerifier {

	//Message Digest
	private String mdAlgorithm = "SHA-256"
	//Message Authentication Code
	private String macAlgorithm = "HmacSHA256"
	private String charSet = "UTF-8"
	private JsonSlurper jsonSlurper = new JsonSlurper()

	IJiraConnectInfoService jiraConnectInfoService


	/**
	 * @param str
	 * @return
	 */
	private String getQueryStringHash(String str) {
		try {
			MessageDigest md = MessageDigest.getInstance(mdAlgorithm)
			md.update(str.getBytes(charSet))
			byte[] digest = md.digest()
			return encodeHexString(digest)
		}catch(NoSuchAlgorithmException e) {
			throw new InsufficientAuthenticationException("Invalid message digest algorithm ${mdAlgorithm} to generate query string hash", e)
		}catch(UnsupportedEncodingException e) {
			throw new InsufficientAuthenticationException("Invalid charset encoder ${charSet} to generate query string hash", e)
		}
	}

	/**
	 * @param signingInput
	 * @param sharedSecret
	 * @return
	 */
	private String signHmac256(String signingInput, String sharedSecret) {
		try {
			SecretKey key = new SecretKeySpec(sharedSecret.getBytes(), macAlgorithm)
			Mac mac = Mac.getInstance(macAlgorithm)
			mac.init(key)
			return encodeBase64URLSafeString(mac.doFinal(signingInput.getBytes()))
		}catch(NoSuchAlgorithmException e) {
			throw new InsufficientAuthenticationException("Invalid message authentication code algorithm ${macAlgorithm} to generate signature", e)
		}catch(InvalidKeyException e) {
			throw new InsufficientAuthenticationException("Invalid shared secret key", e)
		}
	}

	/**
	 * @param claimsJsonString
	 * @param headerJsonString
	 * @param sharedSecret
	 * @return
	 */
	private String getSigningInput(String claimsJsonString, String headerJsonString, String sharedSecret) {
		return encodeBase64URLSafeString(headerJsonString.getBytes()) + "." + encodeBase64URLSafeString(claimsJsonString.getBytes())
	}

	/**
	 * @param claimsJsonString
	 * @param headerJsonString
	 * @param sharedSecret
	 * @return
	 */
	private String sign(String claimsJsonString, String headerJsonString, String sharedSecret) {

		if(!sharedSecret) {
			throw new InsufficientAuthenticationException("Shared secret not found to validate jwt token")
		}

		String signingInput = getSigningInput(claimsJsonString, headerJsonString, sharedSecret)
		return signHmac256(signingInput, sharedSecret)
	}

	/**
	 * @param jwt
	 * @return
	 */
	public def getJwtSegments(String jwt) {
		List base64UrlEncodedSegments = jwt.tokenize(".");

		if(base64UrlEncodedSegments.isEmpty() || base64UrlEncodedSegments.size() < 3) {
			throw new InsufficientAuthenticationException("Invalid jwt ${jwt} token")
		}

		String base64UrlEncodedHeader = new String(base64UrlEncodedSegments[0].toString().decodeBase64())
		String base64UrlEncodedClaims = new String(base64UrlEncodedSegments[1].toString().decodeBase64())
		String signature = base64UrlEncodedSegments[2]

		if(!base64UrlEncodedHeader || !base64UrlEncodedClaims || !signature) {
			throw new InsufficientAuthenticationException("Invalid jwt ${jwt} token")
		}

		return [base64UrlEncodedHeader, base64UrlEncodedClaims, signature]
	}


	/**
	 * To verify claims segment from JWT token, parsing it
	 * into object form from JSON string then validate each fields of it
	 * 
	 * @param jwtRequest
	 * @param base64UrlEncodedClaims
	 */
	private JiraConnectInfo verifyClaims(JwtRequest jwtRequest, String base64UrlEncodedClaims) {

		def claimsObj

		try {
			claimsObj = jsonSlurper.parseText(base64UrlEncodedClaims)
		}catch(e) {
			throw new InsufficientAuthenticationException("Invalid token claims format, it should be in json format")
		}

		if(!claimsObj) {
			throw new InsufficientAuthenticationException("Invalid token claims")
		}

		//Convert JSON to object to prepare claim
		JwtClaims claims = new JwtClaims(claimsObj)

		//Verify expiry time
		//reference link https://currentmillis.com/tutorials/system-currentTimeMillis.html
		long expiryUTCUnixTime = claims.exp
		long currentUTCUnixTime = (System.currentTimeMillis() / 1000L) //Instant.now().epochSecond

		if(expiryUTCUnixTime < currentUTCUnixTime) {
			throw new InsufficientAuthenticationException("Request token is expired")
		}

		//Get JIRA connect info to verify claims
		//Here issuer key which is same as client key
		JiraConnectInfo jiraConnect = jiraConnectInfoService.loadByClientKey(claims.iss)

		if(!jiraConnect) {
			throw new InsufficientAuthenticationException("Invalid cliams issuer")
		}

		//Now verify query string hash
		//Generate Query string hash from input
		String canonicalUrl = jwtRequest.methodName + '&'+ jwtRequest.path + '&' + jwtRequest.queryString
		String generatedQsh = getQueryStringHash(canonicalUrl)

		//Now verify Query string hash
		if(generatedQsh != claims.qsh) {
			throw new InsufficientAuthenticationException("Query string hash is invalid")
		}

		return jiraConnect
	}

	/**
	 * To verify JWT token from request, find all segments from
	 * token and verify each of them
	 * @param jwtRequest
	 * @return
	 */
	public JiraConnectInfo verifyRequest(JwtRequest jwtRequest) {
		JiraConnectInfo jiraConnect

		if(jwtRequest.jwt) {

			def (base64UrlEncodedHeader, base64UrlEncodedClaims, signature) = getJwtSegments(jwtRequest.jwt)

			//Now verify claims first
			jiraConnect = verifyClaims(jwtRequest, base64UrlEncodedClaims)

			//Now generate signature and verify
			String generatedSignature = sign(base64UrlEncodedClaims, base64UrlEncodedHeader, jiraConnect.sharedSecret)

			if(generatedSignature != signature) {
				throw new InsufficientAuthenticationException("Invalid jwt signature")
			}
		}

		//Now check if request is also for installation
		//Update existing or find details by application key and update with credentials
		if(jwtRequest.isInstallation) {

			//Check and find by application key before update if it is fresh installation
			if(!jiraConnect) {
				//Verify client key and update details into DB
				jiraConnect = jiraConnectInfoService.loadByApplicationKey(jwtRequest.applicationKey)

				//Now verify before update
				if(!jiraConnect) {
					throw new InsufficientAuthenticationException("Invalid application key : ${jwtRequest.applicationKey}")
				}
			}

			jiraConnect.clientKey = jwtRequest.clientKey
			jiraConnect.publicKey = jwtRequest.publicKey
			jiraConnect.sharedSecret = jwtRequest.sharedSecret
			jiraConnect.description = jwtRequest.description

			jiraConnect = jiraConnectInfoService.updateJiraConnectInfo(jiraConnect)
		}

		return jiraConnect
	}
}