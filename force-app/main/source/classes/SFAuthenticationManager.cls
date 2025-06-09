/**
 * Service class to handle OAuth 2.0 authentication with Salesforce
 * STUDENT VERSION - Complete the method implementations
 */
public class SFAuthenticationManager {
	// Endpoint for token requests
	private static final String TOKEN_ENDPOINT = '/services/oauth2/token';
	private static final String AUTHORIZE_ENDPOINT = '/services/oauth2/authorize';
	private static final String PKCE_GENERATOR_ENDPOINT = '/services/oauth2/pkce/generator';

	// Configuration values
	public static final String DEFAULT_CLIENT_ID = 'DUMMY_CLIENT_ID';
	public static final String DEFAULT_CLIENT_SECRET = 'DUMMY_CLIENT_SECRET';
	public static final String DEFAULT_LOGIN_URL = 'https://cloobees142-dev-ed.develop.my.salesforce.com';
	public static final String DEFAULT_REDIRECT_URL = 'https://creative-wolf-kdxrqb-dev-ed.trailblaze.my.site.com/callback';

	/**
	 * Central method to make OAuth token requests
	 * TODO: Complete this method implementation
	 * @param params Map of parameters to include in the request
	 * @param tokenUrl The full URL to the token endpoint
	 * @return Authentication response with token details or error
	 */
	private static AuthResponse makeTokenRequest(Map<String, String> params, String tokenUrl) {

		HttpRequest req = new HttpRequest();
		req.setEndpoint(tokenUrl);	
		req.setMethod('POST');
		req.setHeader('Content-Type', 'application/x-www-form-urlencoded');

		String body = '';
		for (String key : params.keySet()) {
			if (body.length() > 0) {
				body += '&';
			}
			body += key + '=' + params.get(key);
		}	

		req.setBody(body);	
		Http http = new Http();
		AuthResponse authResponse = new AuthResponse();

		try {
			HttpResponse res = http.send(req);
			String responseBody = res.getBody();
			if (responseBody != null && responseBody.trim() != '') {
				Map<String, Object> responseMap = (Map<String, Object>) JSON.deserializeUntyped(responseBody);
				authResponse.isSuccess = true;
				authResponse.accessToken = (String) responseMap.get('access_token');
				authResponse.refreshToken = (String) responseMap.get('refresh_token');
				authResponse.instanceUrl = (String) responseMap.get('instance_url');
				authResponse.tokenType = (String) responseMap.get('token_type');
				authResponse.expiresIn = (Integer) responseMap.get('expires_in');
			} else {
				authResponse.isSuccess = false;
				authResponse.errorMessage = 'Empty response body from server (success status)';
				authResponse.errorDetails = 'No content returned in HTTP response body.';
			}
			
		} catch (Exception e) {
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Exception: ' + e.getMessage();
			authResponse.errorDetails = e.getStackTraceString();
			
		}
		return authResponse;
	
	}

	/**
	 * Authenticate using username and password flow (grant_type=password)
	 * TODO: Complete this method implementation
	 * @param username Username for the org
	 * @param password Password + Security Token
	 * @param securityToken Security Token
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithPassword(
		String username,
		String password,
		String securityToken
	) {
		
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'password',
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'username' => username,
			'password' => password + securityToken
		};
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		AuthResponse authResponse = makeTokenRequest(params, tokenUrl);
		return authResponse;
	}

	/**
	 * Authenticate using client credentials flow (grant_type=client_credentials)
	 * TODO: Complete this method implementation
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithClientCredentials() {
		
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'client_credentials',
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET
		};

		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		AuthResponse authResponse = makeTokenRequest(params, tokenUrl);
		return authResponse;
	}

	/**
	 * JWT Bearer Token Flow authentication
	 * TODO: Complete this method implementation
	 * @param username Username for the org
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithJWT(String username) {
		Auth.JWT jwt = new Auth.JWT();
		jwt.setSub(username);
		jwt.setAud('https://login.salesforce.com');
		jwt.setIss(DEFAULT_CLIENT_ID);
		
		Auth.JWS jws = new Auth.JWS(jwt, 'jwtCertificate');
		String token = jws.getCompactSerialization();
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;

		Auth.JWTBearerTokenExchange jwtExchange = new Auth.JWTBearerTokenExchange(tokenUrl,jws);

		AuthResponse authResponse = new AuthResponse();
		authResponse.isSuccess = true;
		authResponse.accessToken = jwtExchange.getAccessToken();
		authResponse.instanceUrl = DEFAULT_LOGIN_URL;
		authResponse.tokenType = 'Bearer';
		authResponse.expiresIn = 3600;
		return authResponse;
	}

	/**
	 * Generate the authorization URL for Web Server Flow
	 * TODO: Complete this method implementation
	 * @param state Optional state parameter for CSRF protection
	 * @return Full authorization URL
	 */
	@AuraEnabled
	public static String generateAuthorizationUrl(String state) {
		String url = DEFAULT_LOGIN_URL + AUTHORIZE_ENDPOINT + '?';
		url += 'client_id=' + EncodingUtil.urlEncode(DEFAULT_CLIENT_ID, 'UTF-8');
		url += '&redirect_uri=' + EncodingUtil.urlEncode(DEFAULT_REDIRECT_URL, 'UTF-8');
		url += '&response_type=code';
		if (String.isNotBlank(state)) {
			url += '&state=' + EncodingUtil.urlEncode(state, 'UTF-8');
		}
		return url;
	}

	/**
	 * Generate PKCE data for OAuth 2.0 authorization
	 * TODO: Complete this method implementation
	 * @return PkceResponse containing code verifier and challenge
	 */
	@AuraEnabled
	public static PkceResponse generatePkceData() {

		HttpRequest request = new HttpRequest();
		request.setEndpoint(DEFAULT_LOGIN_URL + PKCE_GENERATOR_ENDPOINT);
		request.setMethod('GET');
		request.setHeader('Content-Type', 'application/json');
		
		Http http = new Http();
		PkceResponse pkceResponse = new PkceResponse();

		try {
			HttpResponse response = http.send(request);
			if (response.getStatusCode() == 200) {
				Map<String, Object> responseMap = (Map<String, Object>) JSON.deserializeUntyped(response.getBody());
				pkceResponse.isSuccess = true;
				pkceResponse.codeVerifier = (String) responseMap.get('code_verifier');
				pkceResponse.codeChallenge = (String) responseMap.get('code_challenge');
				pkceResponse.codeChallengeMethod = (String) responseMap.get('code_challenge_method');
			} else {
				pkceResponse.isSuccess = false;
				pkceResponse.errorMessage = 'PKCE error: ' + response.getStatus();
				pkceResponse.errorDetails = response.getBody();
			}
		} catch (Exception e) {
			pkceResponse.isSuccess = false;
			pkceResponse.errorMessage = 'Exception: ' + e.getMessage();
		}
		return pkceResponse;
	}

	/**
	 * Generate authorization URL with PKCE support
	 * TODO: Complete this method implementation
	 * @param usePkce Whether to include PKCE parameters
	 * @param codeChallenge Code challenge from PKCE generation
	 * @param codeChallengeMethod Code challenge method from PKCE generation
	 * @return Full authorization URL with PKCE parameters if requested
	 */
	@AuraEnabled
	public static String generateAuthorizationUrlWithPkce(
		Boolean usePkce,
		String codeChallenge,
		String codeChallengeMethod
	) {
		String url = DEFAULT_LOGIN_URL + AUTHORIZE_ENDPOINT + '?';
		url += 'client_id=' + EncodingUtil.urlEncode(DEFAULT_CLIENT_ID, 'UTF-8');
		url += '&redirect_uri=' + EncodingUtil.urlEncode(DEFAULT_REDIRECT_URL, 'UTF-8');
		url += '&response_type=code';
		if (usePkce && String.isNotBlank(codeChallenge) && String.isNotBlank(codeChallengeMethod)) {
			url += '&code_challenge=' + EncodingUtil.urlEncode(codeChallenge, 'UTF-8');
			url += '&code_challenge_method=' + EncodingUtil.urlEncode(codeChallengeMethod, 'UTF-8');
		}
		return url;
	}

	/**
	 * Exchange authorization code for access token (grant_type=authorization_code)
	 * TODO: Complete this method implementation
	 * @param code Authorization code received from the redirect
	 * @return Authentication response with token details or error
	 */
	@AuraEnabled
	public static AuthResponse exchangeCodeForToken(String code) {
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'authorization_code',
			'code' => code,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'redirect_uri' => DEFAULT_REDIRECT_URL
		};
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		AuthResponse authResponse = makeTokenRequest(params, tokenUrl);
		return authResponse;
	}

	/**
	 * Exchange authorization code for access token with PKCE support
	 * TODO: Complete this method implementation
	 * @param code Authorization code received from the redirect
	 * @param codeVerifier Code verifier for PKCE
	 * @return Authentication response with token details or error
	 */
	@AuraEnabled
	public static AuthResponse exchangeCodeForTokenWithPkce(String code, String codeVerifier) {
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'authorization_code',
			'code' => code,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'redirect_uri' => DEFAULT_REDIRECT_URL
		};
		if (String.isNotBlank(codeVerifier)) {
			params.put('code_verifier', codeVerifier);
		}

		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;

		AuthResponse authResponse = makeTokenRequest(params, tokenUrl);
		return authResponse;
	}

	/**
	 * Refresh an existing access token using a refresh token
	 * Extra Credit: Implement this method
	 * TODO: Complete this method implementation
	 * @param refreshToken The refresh token from a previous authentication
	 * @return Authentication response with new token details or error
	 */
	public static AuthResponse refreshToken(String refreshToken) {
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'refresh_token',
			'refresh_token' => refreshToken,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET
		};
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		
		AuthResponse authResponse = makeTokenRequest(params, tokenUrl);
		return authResponse;
	}

	/**
	 * Class to encapsulate authentication response
	 */
	public class AuthResponse {
		@AuraEnabled
		public Boolean isSuccess;
		@AuraEnabled
		public String accessToken;
		@AuraEnabled
		public String refreshToken;
		@AuraEnabled
		public String instanceUrl;
		@AuraEnabled
		public String tokenType;
		@AuraEnabled
		public Integer expiresIn;
		@AuraEnabled
		public String errorMessage;
		@AuraEnabled
		public String errorDetails;
	}

	/**
	 * Class to encapsulate PKCE response
	 */
	public class PkceResponse {
		@AuraEnabled
		public Boolean isSuccess;
		@AuraEnabled
		public String codeVerifier;
		@AuraEnabled
		public String codeChallenge;
		@AuraEnabled
		public String codeChallengeMethod;
		@AuraEnabled
		public String errorMessage;
		@AuraEnabled
		public String errorDetails;
	}
}
