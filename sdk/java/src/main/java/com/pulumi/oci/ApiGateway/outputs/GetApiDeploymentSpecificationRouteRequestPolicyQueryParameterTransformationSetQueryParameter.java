// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter {
    /**
     * @return The list of headers.
     * 
     */
    private final List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items;

    @CustomType.Constructor
    private GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter(@CustomType.Parameter("items") List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items) {
        this.items = items;
    }

    /**
     * @return The list of headers.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem... items) {
            return items(List.of(items));
        }        public GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter build() {
            return new GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter(items);
        }
    }
}
