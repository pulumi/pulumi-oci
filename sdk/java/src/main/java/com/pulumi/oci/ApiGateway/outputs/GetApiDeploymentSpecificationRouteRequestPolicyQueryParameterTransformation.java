// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation {
    /**
     * @return Filter parameters from the query string as they pass through the gateway.  The gateway applies filters after other transformations, so any parameters set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters;
    /**
     * @return Rename parameters on the query string as they pass through the gateway.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters;
    /**
     * @return Set parameters on the query string as they pass through the gateway.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters;

    private GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation() {}
    /**
     * @return Filter parameters from the query string as they pass through the gateway.  The gateway applies filters after other transformations, so any parameters set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters() {
        return this.filterQueryParameters;
    }
    /**
     * @return Rename parameters on the query string as they pass through the gateway.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters() {
        return this.renameQueryParameters;
    }
    /**
     * @return Set parameters on the query string as they pass through the gateway.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters() {
        return this.setQueryParameters;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters;
        private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters;
        private List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterQueryParameters = defaults.filterQueryParameters;
    	      this.renameQueryParameters = defaults.renameQueryParameters;
    	      this.setQueryParameters = defaults.setQueryParameters;
        }

        @CustomType.Setter
        public Builder filterQueryParameters(List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter> filterQueryParameters) {
            this.filterQueryParameters = Objects.requireNonNull(filterQueryParameters);
            return this;
        }
        public Builder filterQueryParameters(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationFilterQueryParameter... filterQueryParameters) {
            return filterQueryParameters(List.of(filterQueryParameters));
        }
        @CustomType.Setter
        public Builder renameQueryParameters(List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter> renameQueryParameters) {
            this.renameQueryParameters = Objects.requireNonNull(renameQueryParameters);
            return this;
        }
        public Builder renameQueryParameters(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationRenameQueryParameter... renameQueryParameters) {
            return renameQueryParameters(List.of(renameQueryParameters));
        }
        @CustomType.Setter
        public Builder setQueryParameters(List<GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter> setQueryParameters) {
            this.setQueryParameters = Objects.requireNonNull(setQueryParameters);
            return this;
        }
        public Builder setQueryParameters(GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationSetQueryParameter... setQueryParameters) {
            return setQueryParameters(List.of(setQueryParameters));
        }
        public GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation build() {
            final var o = new GetApiDeploymentSpecificationRouteRequestPolicyQueryParameterTransformation();
            o.filterQueryParameters = filterQueryParameters;
            o.renameQueryParameters = renameQueryParameters;
            o.setQueryParameters = setQueryParameters;
            return o;
        }
    }
}