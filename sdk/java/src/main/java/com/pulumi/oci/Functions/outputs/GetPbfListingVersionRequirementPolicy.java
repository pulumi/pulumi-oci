// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPbfListingVersionRequirementPolicy {
    /**
     * @return Details about why this policy is required and what it will be used for.
     * 
     */
    private String description;
    /**
     * @return Policy required for PBF execution
     * 
     */
    private String policy;

    private GetPbfListingVersionRequirementPolicy() {}
    /**
     * @return Details about why this policy is required and what it will be used for.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Policy required for PBF execution
     * 
     */
    public String policy() {
        return this.policy;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPbfListingVersionRequirementPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String policy;
        public Builder() {}
        public Builder(GetPbfListingVersionRequirementPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.policy = defaults.policy;
        }

        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder policy(String policy) {
            this.policy = Objects.requireNonNull(policy);
            return this;
        }
        public GetPbfListingVersionRequirementPolicy build() {
            final var o = new GetPbfListingVersionRequirementPolicy();
            o.description = description;
            o.policy = policy;
            return o;
        }
    }
}