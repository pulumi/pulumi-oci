// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItem {
    /**
     * @return (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    private String from;
    /**
     * @return (Updatable) The new name of the header.  This name must be unique across transformation policies.
     * 
     */
    private String to;

    private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItem() {}
    /**
     * @return (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    public String from() {
        return this.from;
    }
    /**
     * @return (Updatable) The new name of the header.  This name must be unique across transformation policies.
     * 
     */
    public String to() {
        return this.to;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String from;
        private String to;
        public Builder() {}
        public Builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.from = defaults.from;
    	      this.to = defaults.to;
        }

        @CustomType.Setter
        public Builder from(String from) {
            this.from = Objects.requireNonNull(from);
            return this;
        }
        @CustomType.Setter
        public Builder to(String to) {
            this.to = Objects.requireNonNull(to);
            return this;
        }
        public DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItem build() {
            final var o = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItem();
            o.from = from;
            o.to = to;
            return o;
        }
    }
}