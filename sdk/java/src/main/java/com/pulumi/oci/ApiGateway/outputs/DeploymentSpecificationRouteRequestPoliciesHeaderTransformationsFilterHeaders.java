// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeaders {
    /**
     * @return (Updatable) The list of headers.
     * 
     */
    private List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItem> items;
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    private String type;

    private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeaders() {}
    /**
     * @return (Updatable) The list of headers.
     * 
     */
    public List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItem> items() {
        return this.items;
    }
    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeaders defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItem> items;
        private String type;
        public Builder() {}
        public Builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeaders defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder items(List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeaders build() {
            final var o = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeaders();
            o.items = items;
            o.type = type;
            return o;
        }
    }
}