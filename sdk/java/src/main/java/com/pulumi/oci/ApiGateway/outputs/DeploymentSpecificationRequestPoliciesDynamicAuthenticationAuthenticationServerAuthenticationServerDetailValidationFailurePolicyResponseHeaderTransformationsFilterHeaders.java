// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeadersItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeaders {
    /**
     * @return (Updatable) The list of headers.
     * 
     */
    private @Nullable List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeadersItem> items;
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    private @Nullable String type;

    private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeaders() {}
    /**
     * @return (Updatable) The list of headers.
     * 
     */
    public List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeadersItem> items() {
        return this.items == null ? List.of() : this.items;
    }
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeaders defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeadersItem> items;
        private @Nullable String type;
        public Builder() {}
        public Builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeaders defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder items(@Nullable List<DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeadersItem> items) {
            this.items = items;
            return this;
        }
        public Builder items(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeadersItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {
            this.type = type;
            return this;
        }
        public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeaders build() {
            final var o = new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsFilterHeaders();
            o.items = items;
            o.type = type;
            return o;
        }
    }
}