// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerEngine.outputs.ClusterOptionsOpenIdConnectTokenAuthenticationConfigRequiredClaim;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ClusterOptionsOpenIdConnectTokenAuthenticationConfig {
    /**
     * @return (Updatable) A Base64 encoded public RSA or ECDSA certificates used to signed your identity provider&#39;s web certificate.
     * 
     */
    private @Nullable String caCertificate;
    /**
     * @return (Updatable) A client id that all tokens must be issued for.
     * 
     */
    private @Nullable String clientId;
    /**
     * @return (Updatable) A Base64 encoded string of a Kubernetes OIDC Auth Config file. More info [here](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
     * 
     */
    private @Nullable String configurationFile;
    /**
     * @return (Updatable) JWT claim to use as the user&#39;s group. If the claim is present it must be an array of strings.
     * 
     */
    private @Nullable String groupsClaim;
    /**
     * @return (Updatable) Prefix prepended to group claims to prevent clashes with existing names (such as system:groups).
     * 
     */
    private @Nullable String groupsPrefix;
    /**
     * @return (Updatable) Whether the cluster has OIDC Auth Config enabled. Defaults to false.
     * 
     */
    private Boolean isOpenIdConnectAuthEnabled;
    /**
     * @return (Updatable) URL of the provider that allows the API server to discover public signing keys.  Only URLs that use the https:// scheme are accepted. This is typically the provider&#39;s discovery URL,  changed to have an empty path.
     * 
     */
    private @Nullable String issuerUrl;
    /**
     * @return (Updatable) A key=value pair that describes a required claim in the ID Token. If set, the claim is verified to be present  in the ID Token with a matching value. Repeat this flag to specify multiple claims.
     * 
     */
    private @Nullable List<ClusterOptionsOpenIdConnectTokenAuthenticationConfigRequiredClaim> requiredClaims;
    /**
     * @return (Updatable) The signing algorithms accepted. Default is [&#34;RS256&#34;].
     * 
     */
    private @Nullable List<String> signingAlgorithms;
    /**
     * @return (Updatable) JWT claim to use as the user name. By default sub, which is expected to be a unique identifier of the end  user. Admins can choose other claims, such as email or name, depending on their provider. However, claims  other than email will be prefixed with the issuer URL to prevent naming clashes with other plugins.
     * 
     */
    private @Nullable String usernameClaim;
    /**
     * @return (Updatable) Prefix prepended to username claims to prevent clashes with existing names (such as system:users).  For example, the value oidc: will create usernames like oidc:jane.doe. If this flag isn&#39;t provided and  --oidc-username-claim is a value other than email the prefix defaults to ( Issuer URL )# where  ( Issuer URL ) is the value of --oidc-issuer-url. The value - can be used to disable all prefixing.
     * 
     */
    private @Nullable String usernamePrefix;

    private ClusterOptionsOpenIdConnectTokenAuthenticationConfig() {}
    /**
     * @return (Updatable) A Base64 encoded public RSA or ECDSA certificates used to signed your identity provider&#39;s web certificate.
     * 
     */
    public Optional<String> caCertificate() {
        return Optional.ofNullable(this.caCertificate);
    }
    /**
     * @return (Updatable) A client id that all tokens must be issued for.
     * 
     */
    public Optional<String> clientId() {
        return Optional.ofNullable(this.clientId);
    }
    /**
     * @return (Updatable) A Base64 encoded string of a Kubernetes OIDC Auth Config file. More info [here](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
     * 
     */
    public Optional<String> configurationFile() {
        return Optional.ofNullable(this.configurationFile);
    }
    /**
     * @return (Updatable) JWT claim to use as the user&#39;s group. If the claim is present it must be an array of strings.
     * 
     */
    public Optional<String> groupsClaim() {
        return Optional.ofNullable(this.groupsClaim);
    }
    /**
     * @return (Updatable) Prefix prepended to group claims to prevent clashes with existing names (such as system:groups).
     * 
     */
    public Optional<String> groupsPrefix() {
        return Optional.ofNullable(this.groupsPrefix);
    }
    /**
     * @return (Updatable) Whether the cluster has OIDC Auth Config enabled. Defaults to false.
     * 
     */
    public Boolean isOpenIdConnectAuthEnabled() {
        return this.isOpenIdConnectAuthEnabled;
    }
    /**
     * @return (Updatable) URL of the provider that allows the API server to discover public signing keys.  Only URLs that use the https:// scheme are accepted. This is typically the provider&#39;s discovery URL,  changed to have an empty path.
     * 
     */
    public Optional<String> issuerUrl() {
        return Optional.ofNullable(this.issuerUrl);
    }
    /**
     * @return (Updatable) A key=value pair that describes a required claim in the ID Token. If set, the claim is verified to be present  in the ID Token with a matching value. Repeat this flag to specify multiple claims.
     * 
     */
    public List<ClusterOptionsOpenIdConnectTokenAuthenticationConfigRequiredClaim> requiredClaims() {
        return this.requiredClaims == null ? List.of() : this.requiredClaims;
    }
    /**
     * @return (Updatable) The signing algorithms accepted. Default is [&#34;RS256&#34;].
     * 
     */
    public List<String> signingAlgorithms() {
        return this.signingAlgorithms == null ? List.of() : this.signingAlgorithms;
    }
    /**
     * @return (Updatable) JWT claim to use as the user name. By default sub, which is expected to be a unique identifier of the end  user. Admins can choose other claims, such as email or name, depending on their provider. However, claims  other than email will be prefixed with the issuer URL to prevent naming clashes with other plugins.
     * 
     */
    public Optional<String> usernameClaim() {
        return Optional.ofNullable(this.usernameClaim);
    }
    /**
     * @return (Updatable) Prefix prepended to username claims to prevent clashes with existing names (such as system:users).  For example, the value oidc: will create usernames like oidc:jane.doe. If this flag isn&#39;t provided and  --oidc-username-claim is a value other than email the prefix defaults to ( Issuer URL )# where  ( Issuer URL ) is the value of --oidc-issuer-url. The value - can be used to disable all prefixing.
     * 
     */
    public Optional<String> usernamePrefix() {
        return Optional.ofNullable(this.usernamePrefix);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ClusterOptionsOpenIdConnectTokenAuthenticationConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String caCertificate;
        private @Nullable String clientId;
        private @Nullable String configurationFile;
        private @Nullable String groupsClaim;
        private @Nullable String groupsPrefix;
        private Boolean isOpenIdConnectAuthEnabled;
        private @Nullable String issuerUrl;
        private @Nullable List<ClusterOptionsOpenIdConnectTokenAuthenticationConfigRequiredClaim> requiredClaims;
        private @Nullable List<String> signingAlgorithms;
        private @Nullable String usernameClaim;
        private @Nullable String usernamePrefix;
        public Builder() {}
        public Builder(ClusterOptionsOpenIdConnectTokenAuthenticationConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.caCertificate = defaults.caCertificate;
    	      this.clientId = defaults.clientId;
    	      this.configurationFile = defaults.configurationFile;
    	      this.groupsClaim = defaults.groupsClaim;
    	      this.groupsPrefix = defaults.groupsPrefix;
    	      this.isOpenIdConnectAuthEnabled = defaults.isOpenIdConnectAuthEnabled;
    	      this.issuerUrl = defaults.issuerUrl;
    	      this.requiredClaims = defaults.requiredClaims;
    	      this.signingAlgorithms = defaults.signingAlgorithms;
    	      this.usernameClaim = defaults.usernameClaim;
    	      this.usernamePrefix = defaults.usernamePrefix;
        }

        @CustomType.Setter
        public Builder caCertificate(@Nullable String caCertificate) {

            this.caCertificate = caCertificate;
            return this;
        }
        @CustomType.Setter
        public Builder clientId(@Nullable String clientId) {

            this.clientId = clientId;
            return this;
        }
        @CustomType.Setter
        public Builder configurationFile(@Nullable String configurationFile) {

            this.configurationFile = configurationFile;
            return this;
        }
        @CustomType.Setter
        public Builder groupsClaim(@Nullable String groupsClaim) {

            this.groupsClaim = groupsClaim;
            return this;
        }
        @CustomType.Setter
        public Builder groupsPrefix(@Nullable String groupsPrefix) {

            this.groupsPrefix = groupsPrefix;
            return this;
        }
        @CustomType.Setter
        public Builder isOpenIdConnectAuthEnabled(Boolean isOpenIdConnectAuthEnabled) {
            if (isOpenIdConnectAuthEnabled == null) {
              throw new MissingRequiredPropertyException("ClusterOptionsOpenIdConnectTokenAuthenticationConfig", "isOpenIdConnectAuthEnabled");
            }
            this.isOpenIdConnectAuthEnabled = isOpenIdConnectAuthEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder issuerUrl(@Nullable String issuerUrl) {

            this.issuerUrl = issuerUrl;
            return this;
        }
        @CustomType.Setter
        public Builder requiredClaims(@Nullable List<ClusterOptionsOpenIdConnectTokenAuthenticationConfigRequiredClaim> requiredClaims) {

            this.requiredClaims = requiredClaims;
            return this;
        }
        public Builder requiredClaims(ClusterOptionsOpenIdConnectTokenAuthenticationConfigRequiredClaim... requiredClaims) {
            return requiredClaims(List.of(requiredClaims));
        }
        @CustomType.Setter
        public Builder signingAlgorithms(@Nullable List<String> signingAlgorithms) {

            this.signingAlgorithms = signingAlgorithms;
            return this;
        }
        public Builder signingAlgorithms(String... signingAlgorithms) {
            return signingAlgorithms(List.of(signingAlgorithms));
        }
        @CustomType.Setter
        public Builder usernameClaim(@Nullable String usernameClaim) {

            this.usernameClaim = usernameClaim;
            return this;
        }
        @CustomType.Setter
        public Builder usernamePrefix(@Nullable String usernamePrefix) {

            this.usernamePrefix = usernamePrefix;
            return this;
        }
        public ClusterOptionsOpenIdConnectTokenAuthenticationConfig build() {
            final var _resultValue = new ClusterOptionsOpenIdConnectTokenAuthenticationConfig();
            _resultValue.caCertificate = caCertificate;
            _resultValue.clientId = clientId;
            _resultValue.configurationFile = configurationFile;
            _resultValue.groupsClaim = groupsClaim;
            _resultValue.groupsPrefix = groupsPrefix;
            _resultValue.isOpenIdConnectAuthEnabled = isOpenIdConnectAuthEnabled;
            _resultValue.issuerUrl = issuerUrl;
            _resultValue.requiredClaims = requiredClaims;
            _resultValue.signingAlgorithms = signingAlgorithms;
            _resultValue.usernameClaim = usernameClaim;
            _resultValue.usernamePrefix = usernamePrefix;
            return _resultValue;
        }
    }
}
