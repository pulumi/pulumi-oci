// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParameters {
    /**
     * @return (Updatable) The list of query parameters.
     * 
     */
    private List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersItem> items;

    private DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParameters() {}
    /**
     * @return (Updatable) The list of query parameters.
     * 
     */
    public List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParameters defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersItem> items;
        public Builder() {}
        public Builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParameters defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParameters", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersItem... items) {
            return items(List.of(items));
        }
        public DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParameters build() {
            final var _resultValue = new DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParameters();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
