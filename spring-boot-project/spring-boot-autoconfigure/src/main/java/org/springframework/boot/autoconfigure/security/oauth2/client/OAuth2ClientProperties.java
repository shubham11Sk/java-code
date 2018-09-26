/*
 * Copyright 2012-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.autoconfigure.security.oauth2.client;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * OAuth 2.0 client properties.
 *
 * @author Madhura Bhave
 * @author Phillip Webb
 * @author Artsiom Yudovin
 * @author MyeongHyeon Lee
 */
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class OAuth2ClientProperties {

	/**
	 * OAuth provider details.
	 */
	private final Map<String, Provider> provider = new HashMap<>();

	/**
	 * OAuth client registrations.
	 */
	private final Registration registration = new Registration();

	public Map<String, Provider> getProvider() {
		return this.provider;
	}

	public Registration getRegistration() {
		return this.registration;
	}

	@PostConstruct
	public void validate() {
		Map<String, OAuth2ClientProperties.LoginClientRegistration> login = this
				.getRegistration().getLogin();
		Map<String, OAuth2ClientProperties.AuthorizationCodeClientRegistration> authorizationCode = this
				.getRegistration().getAuthorizationCode();
		login.values().forEach(this::validateRegistration);
		authorizationCode.values().forEach(this::validateRegistration);
		this.validateRegistrationId(login.keySet(), authorizationCode.keySet());

	}

	private void validateRegistration(BaseClientRegistration registration) {
		if (!StringUtils.hasText(registration.getClientId())) {
			throw new IllegalStateException("Client id must not be empty.");
		}
	}

	private void validateRegistrationId(Set<String> loginIds,
			Set<String> authorizationCodeIds) {
		Set<String> intersection = new HashSet<>(loginIds);
		intersection.retainAll(authorizationCodeIds);
		if (!intersection.isEmpty()) {
			throw new IllegalStateException(
					"Duplicate key while constructing a mapping: " + intersection);
		}
	}

	public static class Registration {

		/**
		 * OpenID Connect client registrations.
		 */
		private Map<String, LoginClientRegistration> login = new HashMap<>();

		/**
		 * OAuth2 authorization_code client registrations.
		 */
		private Map<String, AuthorizationCodeClientRegistration> authorizationCode = new HashMap<>();

		public Map<String, LoginClientRegistration> getLogin() {
			return this.login;
		}

		public void setLogin(Map<String, LoginClientRegistration> login) {
			this.login = login;
		}

		public Map<String, AuthorizationCodeClientRegistration> getAuthorizationCode() {
			return this.authorizationCode;
		}

		public void setAuthorizationCode(
				Map<String, AuthorizationCodeClientRegistration> authorizationCode) {
			this.authorizationCode = authorizationCode;
		}

	}

	/**
	 * A single client registration for OpenID Connect login.
	 */
	public static class LoginClientRegistration extends BaseClientRegistration {

		/**
		 * Redirect URI. May be left blank when using a pre-defined provider.
		 */
		private String redirectUri;

		public String getRedirectUri() {
			return this.redirectUri;
		}

		public void setRedirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
		}

		@Deprecated
		public String getRedirectUriTemplate() {
			return getRedirectUri();
		}

		@Deprecated
		public void setRedirectUriTemplate(String redirectUri) {
			setRedirectUri(redirectUri);
		}

	}

	/**
	 * A single client registration for OAuth2 authorization_code flow.
	 */
	public static class AuthorizationCodeClientRegistration
			extends BaseClientRegistration {

		/**
		 * Redirect URI for the registration.
		 */
		private String redirectUri;

		public String getRedirectUri() {
			return this.redirectUri;
		}

		public void setRedirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
		}

	}

	/**
	 * Base class for a single client registration.
	 */
	public static class BaseClientRegistration {

		/**
		 * Reference to the OAuth 2.0 provider to use. May reference an element from the
		 * 'provider' property or used one of the commonly used providers (google, github,
		 * facebook, okta).
		 */
		private String provider;

		/**
		 * Client ID for the registration.
		 */
		private String clientId;

		/**
		 * Client secret of the registration.
		 */
		private String clientSecret;

		/**
		 * Client authentication method. May be left blank when using a pre-defined
		 * provider.
		 */
		private String clientAuthenticationMethod;

		/**
		 * Authorization grant type. May be left blank when using a pre-defined provider.
		 */
		private String authorizationGrantType;

		/**
		 * Authorization scopes. May be left blank when using a pre-defined provider.
		 */
		private Set<String> scope;

		/**
		 * Client name. May be left blank when using a pre-defined provider.
		 */
		private String clientName;

		public String getProvider() {
			return this.provider;
		}

		public void setProvider(String provider) {
			this.provider = provider;
		}

		public String getClientId() {
			return this.clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public String getClientSecret() {
			return this.clientSecret;
		}

		public void setClientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
		}

		public String getClientAuthenticationMethod() {
			return this.clientAuthenticationMethod;
		}

		public void setClientAuthenticationMethod(String clientAuthenticationMethod) {
			this.clientAuthenticationMethod = clientAuthenticationMethod;
		}

		public String getAuthorizationGrantType() {
			return this.authorizationGrantType;
		}

		public void setAuthorizationGrantType(String authorizationGrantType) {
			this.authorizationGrantType = authorizationGrantType;
		}

		public Set<String> getScope() {
			return this.scope;
		}

		public void setScope(Set<String> scope) {
			this.scope = scope;
		}

		public String getClientName() {
			return this.clientName;
		}

		public void setClientName(String clientName) {
			this.clientName = clientName;
		}

	}

	public static class Provider {

		/**
		 * Authorization URI for the provider.
		 */
		private String authorizationUri;

		/**
		 * Token URI for the provider.
		 */
		private String tokenUri;

		/**
		 * User info URI for the provider.
		 */
		private String userInfoUri;

		/**
		 * User info authentication method for the provider.
		 */
		private String userInfoAuthenticationMethod;

		/**
		 * Name of the attribute that will be used to extract the username from the call
		 * to 'userInfoUri'.
		 */
		private String userNameAttribute;

		/**
		 * JWK set URI for the provider.
		 */
		private String jwkSetUri;

		/**
		 * URI that an OpenID Connect Provider asserts as its Issuer Identifier.
		 */
		private String issuerUri;

		public String getAuthorizationUri() {
			return this.authorizationUri;
		}

		public void setAuthorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
		}

		public String getTokenUri() {
			return this.tokenUri;
		}

		public void setTokenUri(String tokenUri) {
			this.tokenUri = tokenUri;
		}

		public String getUserInfoUri() {
			return this.userInfoUri;
		}

		public void setUserInfoUri(String userInfoUri) {
			this.userInfoUri = userInfoUri;
		}

		public String getUserInfoAuthenticationMethod() {
			return this.userInfoAuthenticationMethod;
		}

		public void setUserInfoAuthenticationMethod(String userInfoAuthenticationMethod) {
			this.userInfoAuthenticationMethod = userInfoAuthenticationMethod;
		}

		public String getUserNameAttribute() {
			return this.userNameAttribute;
		}

		public void setUserNameAttribute(String userNameAttribute) {
			this.userNameAttribute = userNameAttribute;
		}

		public String getJwkSetUri() {
			return this.jwkSetUri;
		}

		public void setJwkSetUri(String jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
		}

		public String getIssuerUri() {
			return this.issuerUri;
		}

		public void setIssuerUri(String issuerUri) {
			this.issuerUri = issuerUri;
		}

	}

}
