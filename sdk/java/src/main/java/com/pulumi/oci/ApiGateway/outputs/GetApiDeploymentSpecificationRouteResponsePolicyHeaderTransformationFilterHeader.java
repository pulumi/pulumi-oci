// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeader {
    /**
     * @return The list of headers.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItem> items;
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    private String type;

    private GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeader() {}
    /**
     * @return The list of headers.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItem> items() {
        return this.items;
    }
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItem> items;
        private String type;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder items(List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeader build() {
            final var o = new GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeader();
            o.items = items;
            o.type = type;
            return o;
        }
    }
}