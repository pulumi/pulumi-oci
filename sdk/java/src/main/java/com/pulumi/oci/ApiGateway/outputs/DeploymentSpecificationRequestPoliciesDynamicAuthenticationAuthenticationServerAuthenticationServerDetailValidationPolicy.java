// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicy;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyClientDetails;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetails;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy {
    /**
     * @return (Updatable) Additional JWT validation checks.
     * 
     */
    private @Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicy additionalValidationPolicy;
    /**
     * @return (Updatable) Client App Credential details.
     * 
     */
    private @Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyClientDetails clientDetails;
    /**
     * @return (Updatable) Defines whether or not to uphold SSL verification.
     * 
     */
    private @Nullable Boolean isSslVerifyDisabled;
    /**
     * @return (Updatable) The set of static public keys.
     * 
     */
    private @Nullable List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey> keys;
    /**
     * @return (Updatable) The duration for which the introspect URL response should be cached before it is fetched again.
     * 
     */
    private @Nullable Integer maxCacheDurationInHours;
    /**
     * @return (Updatable) Auth endpoint details.
     * 
     */
    private @Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetails sourceUriDetails;
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    private String type;
    /**
     * @return (Updatable) The uri from which to retrieve the key. It must be accessible without authentication.
     * 
     */
    private @Nullable String uri;

    private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy() {}
    /**
     * @return (Updatable) Additional JWT validation checks.
     * 
     */
    public Optional<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicy> additionalValidationPolicy() {
        return Optional.ofNullable(this.additionalValidationPolicy);
    }
    /**
     * @return (Updatable) Client App Credential details.
     * 
     */
    public Optional<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyClientDetails> clientDetails() {
        return Optional.ofNullable(this.clientDetails);
    }
    /**
     * @return (Updatable) Defines whether or not to uphold SSL verification.
     * 
     */
    public Optional<Boolean> isSslVerifyDisabled() {
        return Optional.ofNullable(this.isSslVerifyDisabled);
    }
    /**
     * @return (Updatable) The set of static public keys.
     * 
     */
    public List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey> keys() {
        return this.keys == null ? List.of() : this.keys;
    }
    /**
     * @return (Updatable) The duration for which the introspect URL response should be cached before it is fetched again.
     * 
     */
    public Optional<Integer> maxCacheDurationInHours() {
        return Optional.ofNullable(this.maxCacheDurationInHours);
    }
    /**
     * @return (Updatable) Auth endpoint details.
     * 
     */
    public Optional<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetails> sourceUriDetails() {
        return Optional.ofNullable(this.sourceUriDetails);
    }
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return (Updatable) The uri from which to retrieve the key. It must be accessible without authentication.
     * 
     */
    public Optional<String> uri() {
        return Optional.ofNullable(this.uri);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicy additionalValidationPolicy;
        private @Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyClientDetails clientDetails;
        private @Nullable Boolean isSslVerifyDisabled;
        private @Nullable List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey> keys;
        private @Nullable Integer maxCacheDurationInHours;
        private @Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetails sourceUriDetails;
        private String type;
        private @Nullable String uri;
        public Builder() {}
        public Builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalValidationPolicy = defaults.additionalValidationPolicy;
    	      this.clientDetails = defaults.clientDetails;
    	      this.isSslVerifyDisabled = defaults.isSslVerifyDisabled;
    	      this.keys = defaults.keys;
    	      this.maxCacheDurationInHours = defaults.maxCacheDurationInHours;
    	      this.sourceUriDetails = defaults.sourceUriDetails;
    	      this.type = defaults.type;
    	      this.uri = defaults.uri;
        }

        @CustomType.Setter
        public Builder additionalValidationPolicy(@Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicy additionalValidationPolicy) {
            this.additionalValidationPolicy = additionalValidationPolicy;
            return this;
        }
        @CustomType.Setter
        public Builder clientDetails(@Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyClientDetails clientDetails) {
            this.clientDetails = clientDetails;
            return this;
        }
        @CustomType.Setter
        public Builder isSslVerifyDisabled(@Nullable Boolean isSslVerifyDisabled) {
            this.isSslVerifyDisabled = isSslVerifyDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder keys(@Nullable List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey> keys) {
            this.keys = keys;
            return this;
        }
        public Builder keys(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey... keys) {
            return keys(List.of(keys));
        }
        @CustomType.Setter
        public Builder maxCacheDurationInHours(@Nullable Integer maxCacheDurationInHours) {
            this.maxCacheDurationInHours = maxCacheDurationInHours;
            return this;
        }
        @CustomType.Setter
        public Builder sourceUriDetails(@Nullable DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetails sourceUriDetails) {
            this.sourceUriDetails = sourceUriDetails;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder uri(@Nullable String uri) {
            this.uri = uri;
            return this;
        }
        public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy build() {
            final var o = new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy();
            o.additionalValidationPolicy = additionalValidationPolicy;
            o.clientDetails = clientDetails;
            o.isSslVerifyDisabled = isSslVerifyDisabled;
            o.keys = keys;
            o.maxCacheDurationInHours = maxCacheDurationInHours;
            o.sourceUriDetails = sourceUriDetails;
            o.type = type;
            o.uri = uri;
            return o;
        }
    }
}