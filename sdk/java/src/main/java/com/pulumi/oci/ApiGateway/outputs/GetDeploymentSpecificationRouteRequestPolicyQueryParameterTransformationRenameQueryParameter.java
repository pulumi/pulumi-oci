// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameterItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter {
    /**
     * @return The list of headers.
     * 
     */
    private final List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameterItem> items;

    @CustomType.Constructor
    private GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter(@CustomType.Parameter("items") List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameterItem> items) {
        this.items = items;
    }

    /**
     * @return The list of headers.
     * 
     */
    public List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameterItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameterItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameterItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameterItem... items) {
            return items(List.of(items));
        }        public GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter build() {
            return new GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter(items);
        }
    }
}
