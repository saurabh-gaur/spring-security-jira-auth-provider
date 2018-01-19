package com.jira.jwt.builder

import static org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString
import static org.apache.commons.codec.binary.Hex.encodeHexString

import java.security.*

import javax.crypto.*
import javax.crypto.spec.SecretKeySpec

import com.google.gson.Gson
import com.jira.command.JwtClaims
import com.jira.command.JwtHeader

/**
 * @author Saurabh
 */
class JwtBuilder {

	/**
	 * @param canonicalUrl
	 * @param key
	 * @param sharedSecret
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 */
	public static String generateJWTToken(String canonicalUrl, String key, String sharedSecret) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
		JwtClaims claims = new JwtClaims();
		claims.setIss(key);
		claims.setIat(System.currentTimeMillis() / 1000L);
		claims.setExp(claims.getIat() + 180L);

		claims.setQsh(getQueryStringHash(canonicalUrl));
		String jwtToken = sign(claims, sharedSecret);
		return jwtToken;
	}

	/**
	 * @param claims
	 * @param sharedSecret
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	private static String sign(JwtClaims claims, String sharedSecret) throws InvalidKeyException, NoSuchAlgorithmException {
		String signingInput = getSigningInput(claims, sharedSecret);
		String signed256 = signHmac256(signingInput, sharedSecret);
		return signingInput + "." + signed256;
	}

	/**
	 * @param claims
	 * @param sharedSecret
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	private static String getSigningInput(JwtClaims claims, String sharedSecret) throws InvalidKeyException, NoSuchAlgorithmException {
		JwtHeader header = new JwtHeader();
		header.alg = "HS256";
		header.typ = "JWT";
		Gson gson = new Gson();
		String headerJsonString = gson.toJson(header);
		String claimsJsonString = gson.toJson(claims);
		String signingInput = encodeBase64URLSafeString(headerJsonString.getBytes()) + "." + encodeBase64URLSafeString(claimsJsonString.getBytes());
		return signingInput;
	}

	/**
	 * @param signingInput
	 * @param sharedSecret
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private static String signHmac256(String signingInput, String sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey key = new SecretKeySpec(sharedSecret.getBytes(), "HmacSHA256");
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(key);
		return encodeBase64URLSafeString(mac.doFinal(signingInput.getBytes()));
	}

	/**
	 * @param canonicalUrl
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	private static String getQueryStringHash(String canonicalUrl) throws NoSuchAlgorithmException,UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(canonicalUrl.getBytes("UTF-8"));
		byte[] digest = md.digest();
		return encodeHexString(digest);
	}
}
