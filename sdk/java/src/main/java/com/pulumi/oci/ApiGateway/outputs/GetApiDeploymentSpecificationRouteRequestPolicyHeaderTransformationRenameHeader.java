// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeaderItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader {
    /**
     * @return The list of headers.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeaderItem> items;

    private GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader() {}
    /**
     * @return The list of headers.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeaderItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeaderItem> items;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeaderItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeaderItem... items) {
            return items(List.of(items));
        }
        public GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader build() {
            final var _resultValue = new GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
