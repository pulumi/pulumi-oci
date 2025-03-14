// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter {
    /**
     * @return The list of headers.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items;

    private GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter() {}
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
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameterItem... items) {
            return items(List.of(items));
        }
        public GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter build() {
            final var _resultValue = new GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
