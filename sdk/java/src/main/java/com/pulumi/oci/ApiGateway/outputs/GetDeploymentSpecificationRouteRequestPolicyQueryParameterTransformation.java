// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation {
    /**
     * @return Filter parameters from the query string as they pass through the gateway.  The gateway applies filters after other transformations, so any parameters set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters;
    /**
     * @return Rename parameters on the query string as they pass through the gateway.
     * 
     */
    private List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters;
    /**
     * @return Set parameters on the query string as they pass through the gateway.
     * 
     */
    private List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters;

    private GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation() {}
    /**
     * @return Filter parameters from the query string as they pass through the gateway.  The gateway applies filters after other transformations, so any parameters set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters() {
        return this.filterQueryParameters;
    }
    /**
     * @return Rename parameters on the query string as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters() {
        return this.renameQueryParameters;
    }
    /**
     * @return Set parameters on the query string as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters() {
        return this.setQueryParameters;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters;
        private List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters;
        private List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters;
        public Builder() {}
        public Builder(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterQueryParameters = defaults.filterQueryParameters;
    	      this.renameQueryParameters = defaults.renameQueryParameters;
    	      this.setQueryParameters = defaults.setQueryParameters;
        }

        @CustomType.Setter
        public Builder filterQueryParameters(List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters) {
            this.filterQueryParameters = Objects.requireNonNull(filterQueryParameters);
            return this;
        }
        public Builder filterQueryParameters(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter... filterQueryParameters) {
            return filterQueryParameters(List.of(filterQueryParameters));
        }
        @CustomType.Setter
        public Builder renameQueryParameters(List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters) {
            this.renameQueryParameters = Objects.requireNonNull(renameQueryParameters);
            return this;
        }
        public Builder renameQueryParameters(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter... renameQueryParameters) {
            return renameQueryParameters(List.of(renameQueryParameters));
        }
        @CustomType.Setter
        public Builder setQueryParameters(List<GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters) {
            this.setQueryParameters = Objects.requireNonNull(setQueryParameters);
            return this;
        }
        public Builder setQueryParameters(GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter... setQueryParameters) {
            return setQueryParameters(List.of(setQueryParameters));
        }
        public GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation build() {
            final var o = new GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation();
            o.filterQueryParameters = filterQueryParameters;
            o.renameQueryParameters = renameQueryParameters;
            o.setQueryParameters = setQueryParameters;
            return o;
        }
    }
}