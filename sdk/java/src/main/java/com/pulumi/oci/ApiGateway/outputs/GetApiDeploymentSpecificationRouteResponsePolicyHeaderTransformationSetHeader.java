// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeader {
    /**
     * @return The list of headers.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderItem> items;

    private GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeader() {}
    /**
     * @return The list of headers.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderItem> items;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderItem... items) {
            return items(List.of(items));
        }
        public GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeader build() {
            final var o = new GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeader();
            o.items = items;
            return o;
        }
    }
}