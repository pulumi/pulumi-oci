// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeader {
    /**
     * @return The list of headers.
     * 
     */
    private final List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItem> items;
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeader(
        @CustomType.Parameter("items") List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItem> items,
        @CustomType.Parameter("type") String type) {
        this.items = items;
        this.type = type;
    }

    /**
     * @return The list of headers.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItem> items() {
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

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeader defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItem> items;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
    	      this.type = defaults.type;
        }

        public Builder items(List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItem... items) {
            return items(List.of(items));
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeader build() {
            return new GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeader(items, type);
        }
    }
}
