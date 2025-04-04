// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicySourceUriDetails {
    /**
     * @return (Updatable) Type of the Uri detail.
     * 
     */
    private String type;
    /**
     * @return (Updatable) The discovery URI for the auth server.
     * 
     */
    private @Nullable String uri;

    private DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicySourceUriDetails() {}
    /**
     * @return (Updatable) Type of the Uri detail.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return (Updatable) The discovery URI for the auth server.
     * 
     */
    public Optional<String> uri() {
        return Optional.ofNullable(this.uri);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicySourceUriDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String type;
        private @Nullable String uri;
        public Builder() {}
        public Builder(DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicySourceUriDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.type = defaults.type;
    	      this.uri = defaults.uri;
        }

        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicySourceUriDetails", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder uri(@Nullable String uri) {

            this.uri = uri;
            return this;
        }
        public DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicySourceUriDetails build() {
            final var _resultValue = new DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicySourceUriDetails();
            _resultValue.type = type;
            _resultValue.uri = uri;
            return _resultValue;
        }
    }
}
