// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsIdentityProvidersIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider {
    /**
     * @return Social IDP Access token URL
     * 
     */
    private String accessTokenUrl;
    /**
     * @return Whether account linking is enabled
     * 
     */
    private Boolean accountLinkingEnabled;
    /**
     * @return Admin scope to request
     * 
     */
    private List<String> adminScopes;
    /**
     * @return Social IDP Authorization URL
     * 
     */
    private String authzUrl;
    /**
     * @return Whether the client credential is contained in payload
     * 
     */
    private Boolean clientCredentialInPayload;
    /**
     * @return Social IDP allowed clock skew time
     * 
     */
    private Integer clockSkewInSeconds;
    /**
     * @return Social IDP Client Application Client ID
     * 
     */
    private String consumerKey;
    /**
     * @return Social IDP Client Application Client Secret
     * 
     */
    private String consumerSecret;
    /**
     * @return Discovery URL
     * 
     */
    private String discoveryUrl;
    /**
     * @return Id attribute used for account linking
     * 
     */
    private String idAttribute;
    /**
     * @return Social IDP User profile URL
     * 
     */
    private String profileUrl;
    /**
     * @return redirect URL for social idp
     * 
     */
    private String redirectUrl;
    /**
     * @return Whether registration is enabled
     * 
     */
    private Boolean registrationEnabled;
    /**
     * @return Scope to request
     * 
     */
    private List<String> scopes;
    /**
     * @return Service Provider Name
     * 
     */
    private String serviceProviderName;
    /**
     * @return Status
     * 
     */
    private String status;

    private GetDomainsIdentityProvidersIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider() {}
    /**
     * @return Social IDP Access token URL
     * 
     */
    public String accessTokenUrl() {
        return this.accessTokenUrl;
    }
    /**
     * @return Whether account linking is enabled
     * 
     */
    public Boolean accountLinkingEnabled() {
        return this.accountLinkingEnabled;
    }
    /**
     * @return Admin scope to request
     * 
     */
    public List<String> adminScopes() {
        return this.adminScopes;
    }
    /**
     * @return Social IDP Authorization URL
     * 
     */
    public String authzUrl() {
        return this.authzUrl;
    }
    /**
     * @return Whether the client credential is contained in payload
     * 
     */
    public Boolean clientCredentialInPayload() {
        return this.clientCredentialInPayload;
    }
    /**
     * @return Social IDP allowed clock skew time
     * 
     */
    public Integer clockSkewInSeconds() {
        return this.clockSkewInSeconds;
    }
    /**
     * @return Social IDP Client Application Client ID
     * 
     */
    public String consumerKey() {
        return this.consumerKey;
    }
    /**
     * @return Social IDP Client Application Client Secret
     * 
     */
    public String consumerSecret() {
        return this.consumerSecret;
    }
    /**
     * @return Discovery URL
     * 
     */
    public String discoveryUrl() {
        return this.discoveryUrl;
    }
    /**
     * @return Id attribute used for account linking
     * 
     */
    public String idAttribute() {
        return this.idAttribute;
    }
    /**
     * @return Social IDP User profile URL
     * 
     */
    public String profileUrl() {
        return this.profileUrl;
    }
    /**
     * @return redirect URL for social idp
     * 
     */
    public String redirectUrl() {
        return this.redirectUrl;
    }
    /**
     * @return Whether registration is enabled
     * 
     */
    public Boolean registrationEnabled() {
        return this.registrationEnabled;
    }
    /**
     * @return Scope to request
     * 
     */
    public List<String> scopes() {
        return this.scopes;
    }
    /**
     * @return Service Provider Name
     * 
     */
    public String serviceProviderName() {
        return this.serviceProviderName;
    }
    /**
     * @return Status
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsIdentityProvidersIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String accessTokenUrl;
        private Boolean accountLinkingEnabled;
        private List<String> adminScopes;
        private String authzUrl;
        private Boolean clientCredentialInPayload;
        private Integer clockSkewInSeconds;
        private String consumerKey;
        private String consumerSecret;
        private String discoveryUrl;
        private String idAttribute;
        private String profileUrl;
        private String redirectUrl;
        private Boolean registrationEnabled;
        private List<String> scopes;
        private String serviceProviderName;
        private String status;
        public Builder() {}
        public Builder(GetDomainsIdentityProvidersIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessTokenUrl = defaults.accessTokenUrl;
    	      this.accountLinkingEnabled = defaults.accountLinkingEnabled;
    	      this.adminScopes = defaults.adminScopes;
    	      this.authzUrl = defaults.authzUrl;
    	      this.clientCredentialInPayload = defaults.clientCredentialInPayload;
    	      this.clockSkewInSeconds = defaults.clockSkewInSeconds;
    	      this.consumerKey = defaults.consumerKey;
    	      this.consumerSecret = defaults.consumerSecret;
    	      this.discoveryUrl = defaults.discoveryUrl;
    	      this.idAttribute = defaults.idAttribute;
    	      this.profileUrl = defaults.profileUrl;
    	      this.redirectUrl = defaults.redirectUrl;
    	      this.registrationEnabled = defaults.registrationEnabled;
    	      this.scopes = defaults.scopes;
    	      this.serviceProviderName = defaults.serviceProviderName;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder accessTokenUrl(String accessTokenUrl) {
            this.accessTokenUrl = Objects.requireNonNull(accessTokenUrl);
            return this;
        }
        @CustomType.Setter
        public Builder accountLinkingEnabled(Boolean accountLinkingEnabled) {
            this.accountLinkingEnabled = Objects.requireNonNull(accountLinkingEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder adminScopes(List<String> adminScopes) {
            this.adminScopes = Objects.requireNonNull(adminScopes);
            return this;
        }
        public Builder adminScopes(String... adminScopes) {
            return adminScopes(List.of(adminScopes));
        }
        @CustomType.Setter
        public Builder authzUrl(String authzUrl) {
            this.authzUrl = Objects.requireNonNull(authzUrl);
            return this;
        }
        @CustomType.Setter
        public Builder clientCredentialInPayload(Boolean clientCredentialInPayload) {
            this.clientCredentialInPayload = Objects.requireNonNull(clientCredentialInPayload);
            return this;
        }
        @CustomType.Setter
        public Builder clockSkewInSeconds(Integer clockSkewInSeconds) {
            this.clockSkewInSeconds = Objects.requireNonNull(clockSkewInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder consumerKey(String consumerKey) {
            this.consumerKey = Objects.requireNonNull(consumerKey);
            return this;
        }
        @CustomType.Setter
        public Builder consumerSecret(String consumerSecret) {
            this.consumerSecret = Objects.requireNonNull(consumerSecret);
            return this;
        }
        @CustomType.Setter
        public Builder discoveryUrl(String discoveryUrl) {
            this.discoveryUrl = Objects.requireNonNull(discoveryUrl);
            return this;
        }
        @CustomType.Setter
        public Builder idAttribute(String idAttribute) {
            this.idAttribute = Objects.requireNonNull(idAttribute);
            return this;
        }
        @CustomType.Setter
        public Builder profileUrl(String profileUrl) {
            this.profileUrl = Objects.requireNonNull(profileUrl);
            return this;
        }
        @CustomType.Setter
        public Builder redirectUrl(String redirectUrl) {
            this.redirectUrl = Objects.requireNonNull(redirectUrl);
            return this;
        }
        @CustomType.Setter
        public Builder registrationEnabled(Boolean registrationEnabled) {
            this.registrationEnabled = Objects.requireNonNull(registrationEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder scopes(List<String> scopes) {
            this.scopes = Objects.requireNonNull(scopes);
            return this;
        }
        public Builder scopes(String... scopes) {
            return scopes(List.of(scopes));
        }
        @CustomType.Setter
        public Builder serviceProviderName(String serviceProviderName) {
            this.serviceProviderName = Objects.requireNonNull(serviceProviderName);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public GetDomainsIdentityProvidersIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider build() {
            final var o = new GetDomainsIdentityProvidersIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider();
            o.accessTokenUrl = accessTokenUrl;
            o.accountLinkingEnabled = accountLinkingEnabled;
            o.adminScopes = adminScopes;
            o.authzUrl = authzUrl;
            o.clientCredentialInPayload = clientCredentialInPayload;
            o.clockSkewInSeconds = clockSkewInSeconds;
            o.consumerKey = consumerKey;
            o.consumerSecret = consumerSecret;
            o.discoveryUrl = discoveryUrl;
            o.idAttribute = idAttribute;
            o.profileUrl = profileUrl;
            o.redirectUrl = redirectUrl;
            o.registrationEnabled = registrationEnabled;
            o.scopes = scopes;
            o.serviceProviderName = serviceProviderName;
            o.status = status;
            return o;
        }
    }
}