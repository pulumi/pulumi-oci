// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider {
    /**
     * @return (Updatable) Social IDP Access token URL
     * 
     */
    private @Nullable String accessTokenUrl;
    /**
     * @return (Updatable) Whether account linking is enabled
     * 
     */
    private Boolean accountLinkingEnabled;
    /**
     * @return (Updatable) Admin scope to request
     * 
     */
    private @Nullable List<String> adminScopes;
    /**
     * @return (Updatable) Social IDP Authorization URL
     * 
     */
    private @Nullable String authzUrl;
    /**
     * @return (Updatable) Whether the client credential is contained in payload
     * 
     */
    private @Nullable Boolean clientCredentialInPayload;
    /**
     * @return (Updatable) Social IDP allowed clock skew time
     * 
     */
    private @Nullable Integer clockSkewInSeconds;
    /**
     * @return (Updatable) Social IDP Client Application Client ID
     * 
     */
    private String consumerKey;
    /**
     * @return (Updatable) Social IDP Client Application Client Secret
     * 
     */
    private String consumerSecret;
    /**
     * @return (Updatable) Discovery URL
     * 
     */
    private @Nullable String discoveryUrl;
    /**
     * @return (Updatable) Id attribute used for account linking
     * 
     */
    private @Nullable String idAttribute;
    /**
     * @return (Updatable) Social IDP User profile URL
     * 
     */
    private @Nullable String profileUrl;
    /**
     * @return (Updatable) redirect URL for social idp
     * 
     */
    private @Nullable String redirectUrl;
    /**
     * @return (Updatable) Whether registration is enabled
     * 
     */
    private Boolean registrationEnabled;
    /**
     * @return (Updatable) Scope to request
     * 
     */
    private @Nullable List<String> scopes;
    /**
     * @return (Updatable) Service Provider Name
     * 
     */
    private String serviceProviderName;
    /**
     * @return (Updatable) Status
     * 
     */
    private @Nullable String status;

    private DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider() {}
    /**
     * @return (Updatable) Social IDP Access token URL
     * 
     */
    public Optional<String> accessTokenUrl() {
        return Optional.ofNullable(this.accessTokenUrl);
    }
    /**
     * @return (Updatable) Whether account linking is enabled
     * 
     */
    public Boolean accountLinkingEnabled() {
        return this.accountLinkingEnabled;
    }
    /**
     * @return (Updatable) Admin scope to request
     * 
     */
    public List<String> adminScopes() {
        return this.adminScopes == null ? List.of() : this.adminScopes;
    }
    /**
     * @return (Updatable) Social IDP Authorization URL
     * 
     */
    public Optional<String> authzUrl() {
        return Optional.ofNullable(this.authzUrl);
    }
    /**
     * @return (Updatable) Whether the client credential is contained in payload
     * 
     */
    public Optional<Boolean> clientCredentialInPayload() {
        return Optional.ofNullable(this.clientCredentialInPayload);
    }
    /**
     * @return (Updatable) Social IDP allowed clock skew time
     * 
     */
    public Optional<Integer> clockSkewInSeconds() {
        return Optional.ofNullable(this.clockSkewInSeconds);
    }
    /**
     * @return (Updatable) Social IDP Client Application Client ID
     * 
     */
    public String consumerKey() {
        return this.consumerKey;
    }
    /**
     * @return (Updatable) Social IDP Client Application Client Secret
     * 
     */
    public String consumerSecret() {
        return this.consumerSecret;
    }
    /**
     * @return (Updatable) Discovery URL
     * 
     */
    public Optional<String> discoveryUrl() {
        return Optional.ofNullable(this.discoveryUrl);
    }
    /**
     * @return (Updatable) Id attribute used for account linking
     * 
     */
    public Optional<String> idAttribute() {
        return Optional.ofNullable(this.idAttribute);
    }
    /**
     * @return (Updatable) Social IDP User profile URL
     * 
     */
    public Optional<String> profileUrl() {
        return Optional.ofNullable(this.profileUrl);
    }
    /**
     * @return (Updatable) redirect URL for social idp
     * 
     */
    public Optional<String> redirectUrl() {
        return Optional.ofNullable(this.redirectUrl);
    }
    /**
     * @return (Updatable) Whether registration is enabled
     * 
     */
    public Boolean registrationEnabled() {
        return this.registrationEnabled;
    }
    /**
     * @return (Updatable) Scope to request
     * 
     */
    public List<String> scopes() {
        return this.scopes == null ? List.of() : this.scopes;
    }
    /**
     * @return (Updatable) Service Provider Name
     * 
     */
    public String serviceProviderName() {
        return this.serviceProviderName;
    }
    /**
     * @return (Updatable) Status
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessTokenUrl;
        private Boolean accountLinkingEnabled;
        private @Nullable List<String> adminScopes;
        private @Nullable String authzUrl;
        private @Nullable Boolean clientCredentialInPayload;
        private @Nullable Integer clockSkewInSeconds;
        private String consumerKey;
        private String consumerSecret;
        private @Nullable String discoveryUrl;
        private @Nullable String idAttribute;
        private @Nullable String profileUrl;
        private @Nullable String redirectUrl;
        private Boolean registrationEnabled;
        private @Nullable List<String> scopes;
        private String serviceProviderName;
        private @Nullable String status;
        public Builder() {}
        public Builder(DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider defaults) {
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
        public Builder accessTokenUrl(@Nullable String accessTokenUrl) {
            this.accessTokenUrl = accessTokenUrl;
            return this;
        }
        @CustomType.Setter
        public Builder accountLinkingEnabled(Boolean accountLinkingEnabled) {
            this.accountLinkingEnabled = Objects.requireNonNull(accountLinkingEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder adminScopes(@Nullable List<String> adminScopes) {
            this.adminScopes = adminScopes;
            return this;
        }
        public Builder adminScopes(String... adminScopes) {
            return adminScopes(List.of(adminScopes));
        }
        @CustomType.Setter
        public Builder authzUrl(@Nullable String authzUrl) {
            this.authzUrl = authzUrl;
            return this;
        }
        @CustomType.Setter
        public Builder clientCredentialInPayload(@Nullable Boolean clientCredentialInPayload) {
            this.clientCredentialInPayload = clientCredentialInPayload;
            return this;
        }
        @CustomType.Setter
        public Builder clockSkewInSeconds(@Nullable Integer clockSkewInSeconds) {
            this.clockSkewInSeconds = clockSkewInSeconds;
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
        public Builder discoveryUrl(@Nullable String discoveryUrl) {
            this.discoveryUrl = discoveryUrl;
            return this;
        }
        @CustomType.Setter
        public Builder idAttribute(@Nullable String idAttribute) {
            this.idAttribute = idAttribute;
            return this;
        }
        @CustomType.Setter
        public Builder profileUrl(@Nullable String profileUrl) {
            this.profileUrl = profileUrl;
            return this;
        }
        @CustomType.Setter
        public Builder redirectUrl(@Nullable String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }
        @CustomType.Setter
        public Builder registrationEnabled(Boolean registrationEnabled) {
            this.registrationEnabled = Objects.requireNonNull(registrationEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder scopes(@Nullable List<String> scopes) {
            this.scopes = scopes;
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
        public Builder status(@Nullable String status) {
            this.status = status;
            return this;
        }
        public DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider build() {
            final var o = new DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider();
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